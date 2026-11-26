// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/fim.hpp"
#include "private_state.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <linux/openat2.h>
#include <openssl/evp.h>
#include <sys/syscall.h>
#include <utility>

namespace knetsentry::agent {
namespace {
using private_state::File;
[[nodiscard]] int open_resolved(int directory, const char* name, bool leaf) noexcept {
    open_how how{};
    how.flags = O_PATH | O_CLOEXEC;
    if (!leaf) { how.flags |= O_DIRECTORY; }
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    if (leaf) { how.resolve |= RESOLVE_NO_XDEV; }
    const auto result = ::syscall(SYS_openat2, directory, name, &how, sizeof(how));
    return static_cast<int>(result);
}
[[nodiscard]] bool local_filesystem(int fd) noexcept {
    struct statfs fs{};
    if (::fstatfs(fd, &fs) != 0) { return false; }
    switch (fs.f_type) {
    case EXT4_SUPER_MAGIC: case XFS_SUPER_MAGIC: case BTRFS_SUPER_MAGIC:
    case TMPFS_MAGIC: case OVERLAYFS_SUPER_MAGIC: return true;
    default: return false;
    }
}
// Resolve only configured ancestors, not directory contents. No symlink fallback.
[[nodiscard]] int parent_directory(std::string_view path) {
    File current(::open("/", O_PATH | O_DIRECTORY | O_CLOEXEC));
    if (current.fd < 0 || !local_filesystem(current.fd)) { return -1; }
    path.remove_prefix(1);
    while (path.find('/') != path.npos) {
        const auto slash = path.find('/');
        const std::string component(path.substr(0, slash));
        File next(open_resolved(current.fd, component.c_str(), false));
        if (next.fd < 0 || !local_filesystem(next.fd)) { return -1; }
        std::swap(current.fd, next.fd);
        path.remove_prefix(slash + 1);
    }
    return std::exchange(current.fd, -1);
}
[[nodiscard]] bool same_identity(const struct stat& a, const struct stat& b) noexcept {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
[[nodiscard]] bool same_time(const timespec& a, const timespec& b) noexcept {
    return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
}
[[nodiscard]] bool same_metadata(const struct stat& a, const struct stat& b) noexcept {
    return a.st_mode == b.st_mode && a.st_uid == b.st_uid && a.st_gid == b.st_gid &&
        a.st_nlink == b.st_nlink && a.st_size == b.st_size &&
        same_time(a.st_mtim, b.st_mtim) && same_time(a.st_ctim, b.st_ctim);
}
[[nodiscard]] bool safe_file(const struct stat& st) noexcept {
    return S_ISREG(st.st_mode) && st.st_nlink == 1 && st.st_size >= 0 &&
        static_cast<std::uintmax_t>(st.st_size) <= max_fim_bytes;
}
struct Snapshot {
    bool exists{};
    struct stat metadata{};
    std::array<unsigned char, 32> digest{};
};
struct Watch {
    std::string path;
    std::string leaf;
    struct stat parent{};
    std::unique_ptr<File> anchor;
    Snapshot baseline{};
};
[[nodiscard]] bool parent_matches(const Watch& watch, int fd) noexcept {
    struct stat st{};
    return fd >= 0 && ::fstat(fd, &st) == 0 && same_identity(st, watch.parent);
}
[[nodiscard]] bool snapshot(const Watch& watch, Snapshot& out) {
    File parent(parent_directory(watch.path));
    if (!parent_matches(watch, parent.fd)) { return false; }
    File object(open_resolved(parent.fd, watch.leaf.c_str(), true));
    if (object.fd < 0) {
        if (errno != ENOENT) { return false; }
        File check(parent_directory(watch.path));
        if (!parent_matches(watch, check.fd)) { return false; }
        out = {};
        return true;
    }
    struct stat before{};
    if (::fstat(object.fd, &before) != 0 || !safe_file(before) || !local_filesystem(object.fd)) { return false; }
    // O_PATH cannot trigger device/FIFO reads. Reopen only this already verified
    // regular inode via the kernel's own proc descriptor directory, never the leaf path.
    File proc(::open("/proc/self/fd", O_PATH | O_DIRECTORY | O_CLOEXEC));
    struct statfs proc_fs{};
    if (proc.fd < 0 || ::fstatfs(proc.fd, &proc_fs) != 0 || proc_fs.f_type != PROC_SUPER_MAGIC) { return false; }
    const auto descriptor = std::to_string(object.fd);
    File reader(::openat(proc.fd, descriptor.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    struct stat opened{};
    if (reader.fd < 0 || ::fstat(reader.fd, &opened) != 0 || !safe_file(opened) ||
        !same_identity(before, opened) || !same_metadata(before, opened)) { return false; }
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!digest || EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) != 1) { return false; }
    std::array<unsigned char, 16384> buffer{};
    std::size_t remaining = static_cast<std::size_t>(before.st_size);
    while (remaining != 0) {
        const auto n = ::read(reader.fd, buffer.data(), std::min(remaining, buffer.size()));
        // Fail closed on interrupted or unexpectedly short snapshots; no unbounded retry.
        if (n <= 0 || EVP_DigestUpdate(digest.get(), buffer.data(), static_cast<std::size_t>(n)) != 1) { return false; }
        remaining -= static_cast<std::size_t>(n);
    }
    struct stat after{}, named{};
    File current_parent(parent_directory(watch.path));
    if (!parent_matches(watch, current_parent.fd)) { return false; }
    File current(open_resolved(current_parent.fd, watch.leaf.c_str(), true));
    if (::fstat(reader.fd, &after) != 0 || current.fd < 0 || ::fstat(current.fd, &named) != 0 ||
        !same_identity(before, after) || !same_identity(after, named) ||
        !same_metadata(before, after) || !same_metadata(after, named) || !safe_file(after)) { return false; }
    unsigned int size{};
    if (EVP_DigestFinal_ex(digest.get(), out.digest.data(), &size) != 1 || size != out.digest.size()) { return false; }
    out.exists = true;
    out.metadata = after;
    return true;
}
[[nodiscard]] IntegrityChange compare(const Snapshot& old, const Snapshot& current) noexcept {
    if (!old.exists) { return current.exists ? IntegrityChange::Created : IntegrityChange::None; }
    if (!current.exists) { return IntegrityChange::Deleted; }
    if (!same_identity(old.metadata, current.metadata)) { return IntegrityChange::Replaced; }
    if (old.digest != current.digest) { return IntegrityChange::Content; }
    if (!same_metadata(old.metadata, current.metadata)) { return IntegrityChange::Metadata; }
    return IntegrityChange::None;
}
} // namespace

bool valid_fim_path(std::string_view path) noexcept {
    if (path.size() < 2 || path.size() > 1024 || path.front() != '/') { return false; }
    path.remove_prefix(1);
    for (;;) {
        const auto slash = path.find('/');
        const auto component = path.substr(0, slash);
        if (component.empty() || component.size() > 255 || component == "." || component == "..") { return false; }
        for (const char c : component) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) { return false; }
        }
        if (slash == path.npos) { return true; }
        path.remove_prefix(slash + 1);
    }
}
std::string_view change_name(IntegrityChange change) noexcept {
    switch (change) {
    case IntegrityChange::Created: return "created";
    case IntegrityChange::Deleted: return "deleted";
    case IntegrityChange::Replaced: return "replaced";
    case IntegrityChange::Content: return "content-changed";
    case IntegrityChange::Metadata: return "metadata-changed";
    case IntegrityChange::None: return "none";
    }
    return "unknown";
}
struct IntegrityCollector::Impl {
    explicit Impl(std::vector<std::string> values) : paths(std::move(values)) {}
    std::vector<std::string> paths;
    std::vector<Watch> watches;
    bool running{};
};
IntegrityCollector::IntegrityCollector(std::vector<std::string> paths) : impl_(std::make_unique<Impl>(std::move(paths))) {}
IntegrityCollector::~IntegrityCollector() = default;
bool IntegrityCollector::start() noexcept {
    try {
        if (impl_->running || impl_->paths.empty() || impl_->paths.size() > max_fim_paths) { return false; }
        impl_->watches.clear();
        for (const auto& path : impl_->paths) {
            if (!valid_fim_path(path) || std::count(impl_->paths.begin(), impl_->paths.end(), path) != 1) { return false; }
        }
        for (const auto& path : impl_->paths) {
            Watch watch{path, path.substr(path.rfind('/') + 1), {}, {}, {}};
            watch.anchor = std::make_unique<File>(parent_directory(path));
            if (watch.anchor->fd < 0 || ::fstat(watch.anchor->fd, &watch.parent) != 0 || !snapshot(watch, watch.baseline)) { stop(); return false; }
            impl_->watches.push_back(std::move(watch));
        }
        impl_->running = true;
        return true;
    } catch (...) { stop(); return false; }
}
void IntegrityCollector::stop() noexcept { impl_->running = false; impl_->watches.clear(); }
bool IntegrityCollector::pump(std::array<IntegrityChange, max_fim_paths>& changes) noexcept {
    changes = {};
    if (!impl_->running) { return false; }
    try {
        std::array<Snapshot, max_fim_paths> next{};
        for (std::size_t i = 0; i < impl_->watches.size(); ++i) {
            if (!snapshot(impl_->watches[i], next[i])) { stop(); return false; }
        }
        for (std::size_t i = 0; i < impl_->watches.size(); ++i) {
            changes[i] = compare(impl_->watches[i].baseline, next[i]);
            impl_->watches[i].baseline = next[i];
        }
        return true;
    } catch (...) { stop(); return false; }
}
} // namespace knetsentry::agent

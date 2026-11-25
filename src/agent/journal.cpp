// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/journal.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace knetsentry::agent {
namespace {
constexpr std::size_t max_cursor = 1024;
constexpr std::size_t max_state = 256 * 1024;
constexpr auto state_name = "journal-m52.v1";
constexpr auto pending_name = "journal-m52.pending";
constexpr auto prefix = "KNETSENTRY-JOURNAL-V1\t";
struct File final {
    int fd;
    ~File() { if (fd >= 0) { ::close(fd); } }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    explicit File(int value) : fd(value) {}
};
int open_directory(std::string_view path) {
    File root(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (root.fd < 0) { return -1; }
    path.remove_prefix(1);
    while (!path.empty()) {
        const auto slash = path.find('/');
        const std::string component(path.substr(0, slash));
        const int next = ::openat(root.fd, component.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0) { return -1; }
        ::close(root.fd);
        root.fd = next;
        if (slash == path.npos) { const int result = root.fd; root.fd = -1; return result; }
        path.remove_prefix(slash + 1);
    }
    return -1;
}
bool directory_private(int fd) {
    struct stat st{};
    struct statfs fs{};
    if (::fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() ||
        (st.st_mode & 07777) != 0700 || ::fstatfs(fd, &fs) != 0) { return false; }
    // Qualified development filesystem classes only. No implicit network-mount fallback.
    switch (fs.f_type) {
    case EXT4_SUPER_MAGIC: case XFS_SUPER_MAGIC: case BTRFS_SUPER_MAGIC:
    case TMPFS_MAGIC: case OVERLAYFS_SUPER_MAGIC: return true;
    default: return false;
    }
}
bool regular_private(int fd) {
    struct stat st{};
    return ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == ::geteuid() &&
        (st.st_mode & 07777) == 0600 && st.st_nlink == 1;
}
bool cursor_valid(std::string_view value) {
    return !value.empty() && value.size() <= max_cursor &&
        std::ranges::all_of(value, [](char c) { return c >= '!' && c <= '~'; });
}
bool id_valid(std::string_view value) {
    return value.size() == 32 && std::ranges::all_of(value, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }) && value != "00000000000000000000000000000000";
}
bool number(std::string_view value, std::uint64_t& out) {
    const auto result = std::from_chars(value.data(), value.data() + value.size(), out);
    return result.ec == std::errc{} && result.ptr == value.data() + value.size();
}
bool record_valid(const JournalRecord& r, std::string_view unit) {
    return r.unit == unit && cursor_valid(r.cursor) && id_valid(r.machine) &&
        id_valid(r.boot) && r.realtime_usec != 0 &&
        r.realtime_usec < (std::uint64_t{1} << 55) && r.monotonic_usec < (std::uint64_t{1} << 55);
}
std::string row(const JournalRecord& r) {
    return r.cursor + '\t' + std::to_string(r.realtime_usec) + '\t' +
        std::to_string(r.monotonic_usec) + '\t' + r.machine + '\t' + r.boot + '\t' + r.unit + '\n';
}
bool parse_row(std::string_view line, JournalRecord& r) {
    std::array<std::string_view, 6> fields{};
    for (std::size_t i = 0; i < fields.size() - 1; ++i) {
        const auto tab = line.find('\t');
        if (tab == line.npos) { return false; }
        fields[i] = line.substr(0, tab);
        line.remove_prefix(tab + 1);
    }
    fields.back() = line;
    r.cursor = fields[0]; r.machine = fields[3]; r.boot = fields[4]; r.unit = fields[5];
    return number(fields[1], r.realtime_usec) && number(fields[2], r.monotonic_usec);
}
bool write_all(int fd, std::string_view text) {
    while (!text.empty()) {
        const auto n = ::write(fd, text.data(), text.size());
        if (n < 0 && errno == EINTR) { continue; }
        if (n <= 0) { return false; }
        text.remove_prefix(static_cast<std::size_t>(n));
    }
    return true;
}
} // namespace
bool valid_journal_unit(std::string_view unit) noexcept {
    return unit.size() > 8 && unit.size() <= 128 && unit.ends_with(".service") &&
        std::ranges::all_of(unit, [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '@';
        });
}
bool valid_journal_directory(std::string_view path) noexcept {
    if (path.size() < 2 || path.size() > 4095 || path.front() != '/' || path.back() == '/') { return false; }
    path.remove_prefix(1);
    while (!path.empty()) {
        const auto slash = path.find('/');
        const auto part = path.substr(0, slash);
        if (part.empty() || part == "." || part == ".." ||
            !std::ranges::all_of(part, [](char c) { return c >= ' ' && c <= '~'; })) { return false; }
        if (slash == path.npos) { return true; }
        path.remove_prefix(slash + 1);
    }
    return false;
}
JournalCollector::JournalCollector(JournalSource& source, std::string unit, std::string directory)
    : source_(source), unit_(std::move(unit)), directory_(std::move(directory)) {}
bool JournalCollector::fail(const char* reason) noexcept {
    error_ = reason;
    stop();
    return false;
}
void JournalCollector::stop() noexcept {
    running_ = false;
    source_.close();
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
}
bool JournalCollector::load() {
    state_ = std::string(prefix) + unit_ + '\n';
    const std::string header = state_;
    File file(::openat(fd_, state_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.fd < 0) { return errno == ENOENT; }
    if (!regular_private(file.fd)) { return false; }
    state_.clear();
    std::array<char, 4096> buffer{};
    for (;;) {
        const auto n = ::read(file.fd, buffer.data(), buffer.size());
        if (n < 0 && errno == EINTR) { continue; }
        if (n < 0) { return false; }
        if (n == 0) { break; }
        state_.append(buffer.data(), static_cast<std::size_t>(n));
        if (state_.size() > max_state) { return false; }
    }
    if (!state_.starts_with(header)) { return false; }
    std::string_view rest(state_);
    rest.remove_prefix(header.size());
    while (!rest.empty()) {
        const auto end = rest.find('\n');
        if (end == rest.npos || ++count_ > max_records) { return false; }
        JournalRecord record;
        if (!parse_row(rest.substr(0, end), record) || !record_valid(record, unit_) ||
            std::ranges::find(seen_, record.cursor) != seen_.end()) { return false; }
        cursor_ = record.cursor;
        seen_.push_back(cursor_);
        rest.remove_prefix(end + 1);
    }
    return true;
}
bool JournalCollector::start() noexcept {
    if (started_ || !valid_journal_unit(unit_) || !valid_journal_directory(directory_)) { return false; }
    started_ = true;
    try {
        fd_ = open_directory(directory_);
        if (fd_ < 0 || !directory_private(fd_) || ::flock(fd_, LOCK_EX | LOCK_NB) != 0) {
            return fail("unsafe or busy state directory");
        }
        if (!load()) { return fail("invalid or inaccessible state"); }
        // A crash before rename leaves only an uncommitted temporary file. Never
        // unlink an unverified object, and never use pending contents as a cursor.
        File pending(::openat(fd_, pending_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (pending.fd >= 0) {
            if (!regular_private(pending.fd) || ::unlinkat(fd_, pending_name, 0) != 0 ||
                ::fsync(fd_) != 0) { return fail("unsafe pending state"); }
        } else if (errno != ENOENT) { return fail("unsafe pending state"); }
        if (!source_.open(unit_)) { return fail("journal open failed"); }
        if (!source_.resume(cursor_)) { return fail("journal checkpoint unavailable"); }
        running_ = true;
        error_ = "none";
        return true;
    } catch (...) { return fail("journal startup failed"); }
}
bool JournalCollector::commit(const JournalRecord& record) {
    if (!directory_private(fd_)) { return false; }
    const auto next = state_ + row(record);
    if (next.size() > max_state) { return false; }
    File pending(::openat(fd_, pending_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (pending.fd < 0 || !regular_private(pending.fd) || !write_all(pending.fd, next) ||
        ::fsync(pending.fd) != 0 || ::renameat(fd_, pending_name, fd_, state_name) != 0 ||
        ::fsync(fd_) != 0) { return false; }
    state_ = next;
    cursor_ = record.cursor;
    seen_.push_back(cursor_);
    ++count_;
    return true;
}
bool JournalCollector::pump() noexcept {
    if (!running_) { return false; }
    try {
        if (!directory_private(fd_)) { return fail("unsafe state directory"); }
        if (!source_.resume(cursor_)) { return fail("journal checkpoint unavailable"); }
        for (std::size_t i = 0; i < batch_size; ++i) {
            JournalRecord record;
            const auto result = source_.next(record);
            if (result == JournalResult::End) { return true; }
            if (result != JournalResult::Record || !record_valid(record, unit_) ||
                std::ranges::find(seen_, record.cursor) != seen_.end()) { return fail("invalid journal record"); }
            if (count_ >= max_records) { return fail("journal state capacity reached"); }
            if (!commit(record)) { return fail("journal state commit failed"); }
        }
        return true;
    } catch (...) { return fail("journal collection failed"); }
}
} // namespace knetsentry::agent

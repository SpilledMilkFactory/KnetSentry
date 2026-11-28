// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstddef>
#include <fcntl.h>
#include <optional>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace knetsentry::desktop {
// Fixed schema: presentation only. No strings, paths, or operational state.
struct WorkspacePreferences {
    int ratio{50};
    int sections{7}; // charts=1, health=2, local telemetry=4
    bool operator==(const WorkspacePreferences&) const = default;
};
inline constexpr bool valid_workspace(WorkspacePreferences value) noexcept {
    return value.ratio >= 30 && value.ratio <= 70 && value.ratio % 5 == 0 &&
           value.sections >= 0 && value.sections <= 7;
}
inline constexpr std::string_view workspace_file = "layout.v1";
inline constexpr std::string_view workspace_directory = "knetsentry-workspace";
inline constexpr std::optional<WorkspacePreferences> decode_workspace(std::string_view text) noexcept {
    if (text.size() != 10 || text.substr(0, 5) != "KSW1:" || text[7] != ':' || text[9] != '\n' ||
        text[5] < '0' || text[5] > '9' || text[6] < '0' || text[6] > '9' || text[8] < '0' || text[8] > '7') {
        return std::nullopt;
    }
    const WorkspacePreferences value{(text[5] - '0') * 10 + text[6] - '0', text[8] - '0'};
    return valid_workspace(value) ? std::optional{value} : std::nullopt;
}
inline constexpr std::array<char, 10> encode_workspace(WorkspacePreferences value) noexcept {
    return {'K', 'S', 'W', '1', ':', static_cast<char>('0' + value.ratio / 10),
            static_cast<char>('0' + value.ratio % 10), ':', static_cast<char>('0' + value.sections), '\n'};
}
class WorkspaceFd {
public:
    explicit WorkspaceFd(int fd) noexcept : fd_(fd) {}
    ~WorkspaceFd() { if (fd_ >= 0) { (void)::close(fd_); } }
    WorkspaceFd(const WorkspaceFd&) = delete;
    WorkspaceFd& operator=(const WorkspaceFd&) = delete;
    [[nodiscard]] int get() const noexcept { return fd_; }
private:
    int fd_;
};
inline bool private_workspace_directory(int fd) noexcept {
    struct stat state{};
    return fd >= 0 && ::fstat(fd, &state) == 0 && S_ISDIR(state.st_mode) &&
           state.st_uid == ::geteuid() && (state.st_mode & 07777) == 0700;
}
inline bool private_workspace_file(const struct stat& state) noexcept {
    return S_ISREG(state.st_mode) && state.st_uid == ::geteuid() &&
           (state.st_mode & 07777) == 0600 && state.st_nlink == 1;
}
// Config root is selected by the desktop, never by a saved preference.
inline int open_workspace_directory(const char* root, bool create) noexcept {
    const WorkspaceFd base(::open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    struct stat state{};
    if (base.get() < 0 || ::fstat(base.get(), &state) != 0 || state.st_uid != ::geteuid() ||
        (state.st_mode & 0022) != 0) { return -1; }
    if (create && ::mkdirat(base.get(), workspace_directory.data(), 0700) != 0 && errno != EEXIST) { return -1; }
    const int fd = ::openat(base.get(), workspace_directory.data(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!private_workspace_directory(fd)) { if (fd >= 0) { (void)::close(fd); } return -1; }
    return fd;
}
inline std::optional<WorkspacePreferences> load_workspace(const char* root) noexcept {
    const WorkspaceFd directory(open_workspace_directory(root, false));
    if (directory.get() < 0) { return std::nullopt; }
    struct stat observed{};
    if (::fstatat(directory.get(), workspace_file.data(), &observed, AT_SYMLINK_NOFOLLOW) != 0 ||
        !private_workspace_file(observed) || observed.st_size != 10) { return std::nullopt; }
    const WorkspaceFd file(::openat(directory.get(), workspace_file.data(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    struct stat state{};
    if (file.get() < 0 || ::fstat(file.get(), &state) != 0 || !private_workspace_file(state) || state.st_size != 10 ||
        state.st_dev != observed.st_dev || state.st_ino != observed.st_ino) {
        return std::nullopt;
    }
    std::array<char, 11> bytes{};
    const auto count = ::read(file.get(), bytes.data(), bytes.size());
    if (count != 10) { return std::nullopt; }
    return decode_workspace(std::string_view(bytes.data(), 10));
}
// Atomic replacement in the already opened private directory. A stale temporary
// file is never followed or overwritten; bounded alternate names are tried.
inline bool save_workspace(const char* root, WorkspacePreferences value) noexcept {
    if (!valid_workspace(value)) { return false; }
    const WorkspaceFd directory(open_workspace_directory(root, true));
    if (directory.get() < 0) { return false; }
    struct stat state{};
    if (::fstatat(directory.get(), workspace_file.data(), &state, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!private_workspace_file(state)) { return false; }
    } else if (errno != ENOENT) { return false; }
    const auto bytes = encode_workspace(value);
    for (int attempt = 0; attempt < 16; ++attempt) {
        std::array<char, 64> name{};
        const int length = std::snprintf(name.data(), name.size(), ".layout-%ld-%d", static_cast<long>(::getpid()), attempt);
        if (length < 0 || static_cast<std::size_t>(length) >= name.size()) { return false; }
        const WorkspaceFd file(::openat(directory.get(), name.data(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (file.get() < 0) { if (errno == EEXIST) { continue; } return false; }
        const bool written = ::fchmod(file.get(), 0600) == 0 &&
            ::write(file.get(), bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()) && ::fsync(file.get()) == 0;
        const bool replaced = written && ::renameat(directory.get(), name.data(), directory.get(), workspace_file.data()) == 0;
        if (!replaced) { (void)::unlinkat(directory.get(), name.data(), 0); return false; }
        return ::fsync(directory.get()) == 0;
    }
    return false;
}
} // namespace knetsentry::desktop

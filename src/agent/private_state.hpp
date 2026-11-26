// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <cerrno>
#include <fcntl.h>
#include <linux/magic.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

namespace knetsentry::agent::private_state {
inline constexpr std::size_t max_state = 256 * 1024;
struct File final {
    int fd;
    ~File() { if (fd >= 0) { ::close(fd); } }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    explicit File(int value) : fd(value) {}
};
inline int open_directory(std::string_view path) {
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
inline bool directory_private(int fd) {
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
inline bool regular_private(int fd) {
    struct stat st{};
    return ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == ::geteuid() &&
        (st.st_mode & 07777) == 0600 && st.st_nlink == 1;
}
inline bool write_all(int fd, std::string_view text) {
    while (!text.empty()) {
        const auto n = ::write(fd, text.data(), text.size());
        if (n < 0 && errno == EINTR) { continue; }
        if (n <= 0) { return false; }
        text.remove_prefix(static_cast<std::size_t>(n));
    }
    return true;
}
} // namespace knetsentry::agent::private_state

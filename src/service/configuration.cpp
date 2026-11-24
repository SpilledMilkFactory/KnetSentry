// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/configuration.hpp"

#include <array>
#include <cerrno>
#include <algorithm>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace knetsentry::service {
namespace {
constexpr std::size_t max_bytes = 4096;
constexpr std::size_t max_lines = 32;
constexpr std::size_t key_count = 7;

[[nodiscard]] std::string_view strip_spaces(std::string_view value) noexcept {
    while (!value.empty() && value.front() == ' ') { value.remove_prefix(1); }
    while (!value.empty() && value.back() == ' ') { value.remove_suffix(1); }
    return value;
}

[[nodiscard]] ConfigurationResult failure(ConfigurationError error) noexcept {
    return {.value = {}, .error = error};
}

[[nodiscard]] bool valid_path(std::string_view path) noexcept {
    if (path.empty() || path.size() > 1024 || path.front() != '/') { return false; }
    std::size_t start = 1;
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto part = path.substr(start, end == std::string_view::npos ?
            end : end - start);
        if (part.empty() || part == "." || part == "..") { return false; }
        for (const auto ch : part) {
            if (static_cast<unsigned char>(ch) < 0x21U ||
                static_cast<unsigned char>(ch) > 0x7eU) { return false; }
        }
        if (end == std::string_view::npos) { return true; }
        start = end + 1;
    }
    return false;
}

[[nodiscard]] bool same_identity(const struct stat& a, const struct stat& b) noexcept {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino &&
        a.st_size == b.st_size && a.st_mtim.tv_sec == b.st_mtim.tv_sec &&
        a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
        a.st_ctim.tv_sec == b.st_ctim.tv_sec &&
        a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
} // namespace

ConfigurationResult parse_configuration(std::string_view text) noexcept {
    if (text.empty()) { return failure(ConfigurationError::Empty); }
    if (text.size() > max_bytes) { return failure(ConfigurationError::TooLarge); }
    constexpr std::array<std::string_view, key_count> keys{{
        "schema_version", "mode", "monitoring_enabled", "network_listeners_enabled",
        "packet_capture_enabled", "public_intelligence_enabled", "privileged_actions_enabled"
    }};
    std::array<bool, key_count> present{};
    std::size_t position = 0;
    std::size_t lines = 0;
    while (position < text.size()) {
        if (++lines > max_lines) { return failure(ConfigurationError::TooLarge); }
        const auto end = text.find('\n', position);
        const auto line = text.substr(position, end == std::string_view::npos ?
            end : end - position);
        // Reject all controls, non-ASCII, BOM, escapes, tab, CR and NUL.
        for (const auto ch : line) {
            if (static_cast<unsigned char>(ch) < 0x20U ||
                static_cast<unsigned char>(ch) > 0x7eU) {
                return failure(ConfigurationError::Syntax);
            }
        }
        const auto trimmed = strip_spaces(line);
        if (!trimmed.empty() && trimmed.front() != '#') {
            const auto separator = trimmed.find('=');
            if (separator == std::string_view::npos ||
                trimmed.find('=', separator + 1) != std::string_view::npos) {
                return failure(ConfigurationError::Syntax);
            }
            const auto key = strip_spaces(trimmed.substr(0, separator));
            const auto value = strip_spaces(trimmed.substr(separator + 1));
            std::size_t index = 0;
            while (index < keys.size() && keys[index] != key) { ++index; }
            if (index == keys.size()) { return failure(ConfigurationError::UnknownField); }
            if (present[index]) { return failure(ConfigurationError::DuplicateField); }
            present[index] = true;
            if (index == 0) {
                if (value != "1") { return failure(ConfigurationError::UnsupportedVersion); }
            } else if (index == 1) {
                if (value != "lifecycle_only") {
                    return failure(ConfigurationError::UnsafeSetting);
                }
            } else if (value != "false") {
                return failure(ConfigurationError::UnsafeSetting);
            }
        }
        if (end == std::string_view::npos) { break; }
        position = end + 1;
    }
    for (const auto seen : present) {
        if (!seen) { return failure(ConfigurationError::MissingField); }
    }
    return {};
}

ConfigurationResult load_configuration(std::string_view path) noexcept {
    if (!valid_path(path)) { return failure(ConfigurationError::UnsafePath); }
    // Construct a bounded path only after ASCII/length validation.
    std::array<char, 1025> name{};
    std::copy(path.begin(), path.end(), name.begin());
    const int fd = ::open(name.data(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) { return failure(ConfigurationError::UnsafeFile); }
    struct stat before{};
    if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != ::geteuid() || before.st_nlink != 1 ||
        (before.st_mode & 0077) != 0 || (before.st_mode & 0111) != 0 ||
        before.st_size <= 0 || before.st_size > static_cast<off_t>(max_bytes)) {
        static_cast<void>(::close(fd));
        return failure(ConfigurationError::UnsafeFile);
    }
    std::array<char, max_bytes + 1> buffer{};
    std::size_t count = 0;
    bool failed = false;
    while (count < buffer.size()) {
        const auto amount = ::read(fd, buffer.data() + count, buffer.size() - count);
        if (amount < 0 && errno == EINTR) { continue; }
        if (amount < 0) { failed = true; break; }
        if (amount == 0) { break; }
        count += static_cast<std::size_t>(amount);
    }
    struct stat after{};
    const bool final_stat_ok = ::fstat(fd, &after) == 0;
    const bool close_ok = ::close(fd) == 0;
    if (!final_stat_ok || !close_ok) { failed = true; }
    if (failed || !same_identity(before, after) ||
        count != static_cast<std::size_t>(before.st_size)) {
        return failure(ConfigurationError::ReadFailure);
    }
    if (count > max_bytes) { return failure(ConfigurationError::TooLarge); }
    return parse_configuration(std::string_view(buffer.data(), count));
}

} // namespace knetsentry::service

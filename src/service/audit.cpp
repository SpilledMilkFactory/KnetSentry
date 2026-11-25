// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/audit.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

namespace knetsentry::service {
namespace {
struct Code { const char* event; const char* outcome; };
[[nodiscard]] Code code(AuditEvent event) noexcept {
    switch (event) {
    case AuditEvent::Starting: return {"manager_starting", "started"};
    case AuditEvent::Ready: return {"manager_ready", "success"};
    case AuditEvent::Stopping: return {"manager_stopping", "started"};
    case AuditEvent::Stopped: return {"manager_stopped", "success"};
    case AuditEvent::Failed: return {"manager_failed", "failure"};
    case AuditEvent::ConfigDefault: return {"configuration_default", "success"};
    case AuditEvent::ConfigValidated: return {"configuration_validated", "success"};
    case AuditEvent::ConfigRejected: return {"configuration_rejected", "denied"};
    case AuditEvent::IpcReady: return {"ipc_ready", "success"};
    case AuditEvent::IpcRejected: return {"ipc_startup_rejected", "denied"};
    case AuditEvent::AuthenticationFailed: return {"authentication_failed", "denied"};
    case AuditEvent::RequestRejected: return {"request_rejected", "denied"};
    case AuditEvent::AdministrativeDenied: return {"administrative_denied", "denied"};
    case AuditEvent::StatusAuthorized: return {"status_authorized", "authorized"};
    case AuditEvent::HealthAuthorized: return {"health_authorized", "authorized"};
    case AuditEvent::AgentsAuthorized: return {"agents_authorized", "authorized"};
    case AuditEvent::TransportFailed: return {"transport_failed", "failure"};
    case AuditEvent::SamplingFailed: return {"sampling_failed", "failure"};
    }
    return {nullptr, nullptr};
}

// Walk from root using pinned descriptors; reject every symlink and dot segment.
[[nodiscard]] int private_directory(std::string_view path) noexcept {
    if (path.size() < 2 || path.size() > 1024 || path.front() != '/' ||
        path.back() == '/' || path.find('\0') != std::string_view::npos) { return -1; }
    int fd = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) { return -1; }
    std::size_t begin = 1;
    while (begin < path.size()) {
        const auto end = path.find('/', begin);
        const auto part = path.substr(begin, end == std::string_view::npos ? end : end - begin);
        if (part.empty() || part == "." || part == ".." || part.size() > 255) {
            static_cast<void>(::close(fd)); return -1;
        }
        std::array<char, 256> name{};
        std::memcpy(name.data(), part.data(), part.size());
        const int next = ::openat(fd, name.data(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        static_cast<void>(::close(fd));
        if (next < 0) { return -1; }
        fd = next;
        if (end == std::string_view::npos) { break; }
        begin = end + 1;
    }
    struct stat info{};
    if (::fstat(fd, &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != ::geteuid() || (info.st_mode & 07777U) != 0700U) {
        static_cast<void>(::close(fd)); return -1;
    }
    return fd;
}

[[nodiscard]] bool safe_file(int fd, std::uint64_t bytes) noexcept {
    struct stat info{};
    return ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_uid == ::geteuid() && info.st_nlink == 1 &&
        (info.st_mode & 07777U) == 0600U && info.st_size >= 0 &&
        static_cast<std::uint64_t>(info.st_size) == bytes;
}
} // namespace

AuditLog::~AuditLog() noexcept {
    if (fd_ >= 0) { static_cast<void>(::close(fd_)); }
}

bool AuditLog::open(std::string_view directory) noexcept {
    if (failed_ || fd_ >= 0) { failed_ = true; return false; }
    failed_ = true;
    std::array<unsigned char, 16> random{};
    if (::getrandom(random.data(), random.size(), GRND_NONBLOCK) !=
        static_cast<ssize_t>(random.size())) { return false; }
    constexpr std::string_view hex = "0123456789abcdef";
    for (std::size_t i = 0; i < random.size(); ++i) {
        session_[2 * i] = hex[random[i] >> 4U];
        session_[2 * i + 1] = hex[random[i] & 0x0fU];
    }
    const int dir = private_directory(directory);
    if (dir < 0) { return false; }
    // Never reopen, truncate, replace or remove an existing audit file.
    fd_ = ::openat(dir, "service-audit.jsonl", O_WRONLY | O_CREAT | O_EXCL |
        O_APPEND | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    const bool valid = fd_ >= 0 && safe_file(fd_, 0) && ::fsync(dir) == 0;
    static_cast<void>(::close(dir));
    failed_ = !valid;
    return valid;
}

bool AuditLog::record(AuditEvent event, std::optional<AuditActor> actor) noexcept {
    if (failed_) { return false; }
    if (fd_ < 0) { return true; } // explicit lifecycle-only compatibility mode
    const auto labels = code(event);
    if (labels.event == nullptr || (actor && actor->pid <= 0) || !safe_file(fd_, bytes_)) {
        failed_ = true; return false;
    }
    const auto time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::array<char, 128> identity{};
    const int identity_size = actor ? std::snprintf(identity.data(), identity.size(),
        "{\"pid\":%jd,\"uid\":%ju,\"gid\":%ju}", static_cast<std::intmax_t>(actor->pid),
        static_cast<std::uintmax_t>(actor->uid), static_cast<std::uintmax_t>(actor->gid)) :
        std::snprintf(identity.data(), identity.size(), "null");
    if (identity_size < 0 || static_cast<std::size_t>(identity_size) >= identity.size()) {
        failed_ = true; return false;
    }
    std::array<char, max_record> line{};
    const int count = std::snprintf(line.data(), line.size(),
        "{\"schema\":1,\"session\":\"%s\",\"sequence\":%" PRIu64
        ",\"time_unix_ms\":%jd,\"service_pid\":%jd,\"service_uid\":%ju,\"service_gid\":%ju,"
        "\"event\":\"%s\",\"outcome\":\"%s\",\"peer\":%s}\n",
        session_.data(), sequence_ + 1U, static_cast<std::intmax_t>(time),
        static_cast<std::intmax_t>(::getpid()), static_cast<std::uintmax_t>(::geteuid()),
        static_cast<std::uintmax_t>(::getegid()), labels.event, labels.outcome, identity.data());
    if (count <= 0 || static_cast<std::size_t>(count) >= line.size() ||
        static_cast<std::uint64_t>(count) > max_bytes - bytes_) {
        failed_ = true; return false;
    }
    // A short write is an audit gap, not a successful record. Preserve partial
    // evidence and stop; never silently retry after an ambiguous write.
    const auto written = ::write(fd_, line.data(), static_cast<std::size_t>(count));
    if (written != count || ::fsync(fd_) != 0) { failed_ = true; return false; }
    bytes_ += static_cast<std::uint64_t>(count);
    ++sequence_;
    return true;
}
} // namespace knetsentry::service

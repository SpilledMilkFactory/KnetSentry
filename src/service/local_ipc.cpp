// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/local_ipc.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace knetsentry::service {
namespace {
constexpr std::uint32_t max_frame_size = 64;
constexpr int client_deadline_ms = 250;
constexpr std::string_view prefix = "KSIPC/1 STATUS ";
constexpr std::string_view health_prefix = "KSIPC/1 HEALTH ";

[[nodiscard]] bool valid_directory(std::string_view path) noexcept {
    if (path.size() < 2 || path.size() > 1024 ||
        path.front() != '/' || path.back() == '/' ||
        path.find('\0') != std::string_view::npos) { return false; }
    auto begin = std::size_t{1};
    while (begin < path.size()) {
        const auto end = path.find('/', begin);
        const auto part = path.substr(begin, end == std::string_view::npos ? end : end - begin);
        if (part.empty() || part == "." || part == "..") { return false; }
        for (const auto c : part) {
            if (static_cast<unsigned char>(c) < 0x21U ||
                static_cast<unsigned char>(c) > 0x7eU) { return false; }
        }
        if (end == std::string_view::npos) { break; }
        begin = end + 1;
    }
    return true;
}

[[nodiscard]] bool read_exact(int fd, char* out, std::size_t size) noexcept {
    using Clock = std::chrono::steady_clock;
    const auto deadline = Clock::now() + std::chrono::milliseconds(client_deadline_ms);
    std::size_t used = 0;
    while (used < size) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - Clock::now()).count();
        if (left <= 0) { return false; }
        struct pollfd pfd { fd, POLLIN, 0 };
        const auto n = ::poll(&pfd, 1, static_cast<int>(left));
        if (n <= 0 || (pfd.revents & (POLLERR | POLLNVAL)) != 0) { return false; }
        const auto r = ::recv(fd, out + used, size - used, MSG_DONTWAIT);
        if (r == 0) { return false; }
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { continue; }
            return false;
        }
        used += static_cast<std::size_t>(r);
    }
    return true;
}

[[nodiscard]] bool write_exact(int fd, const char* data, std::size_t size) noexcept {
    using Clock = std::chrono::steady_clock;
    const auto deadline = Clock::now() + std::chrono::milliseconds(client_deadline_ms);
    std::size_t used = 0;
    while (used < size) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - Clock::now()).count();
        if (left <= 0) { return false; }
        struct pollfd pfd { fd, POLLOUT, 0 };
        if (::poll(&pfd, 1, static_cast<int>(left)) <= 0 ||
            (pfd.revents & (POLLERR | POLLNVAL)) != 0) { return false; }
        const auto n = ::send(fd, data + used, size - used, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { continue; }
            return false;
        }
        if (n == 0) { return false; }
        used += static_cast<std::size_t>(n);
    }
    return true;
}

[[nodiscard]] bool send_frame(int fd, std::string_view payload, std::size_t limit) noexcept {
    if (payload.empty() || payload.size() > limit || limit > max_health_response_size) { return false; }
    const auto len = static_cast<std::uint32_t>(payload.size());
    const std::array<char, 4> header{
        static_cast<char>((len >> 24U) & 0xffU),
        static_cast<char>((len >> 16U) & 0xffU),
        static_cast<char>((len >> 8U) & 0xffU),
        static_cast<char>(len & 0xffU)};
    return write_exact(fd, header.data(), header.size()) &&
           write_exact(fd, payload.data(), payload.size());
}

[[nodiscard]] bool hex_id(std::string_view id) noexcept {
    if (id.size() != 16) { return false; }
    for (const char c : id) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { return false; }
    }
    return true;
}
} // namespace

bool authorize_local_peer(uid_t peer_uid, gid_t peer_gid,
    uid_t service_uid, gid_t service_gid, IpcAction action) noexcept {
    return peer_uid == service_uid && peer_gid == service_gid &&
        (action == IpcAction::Status || action == IpcAction::Health);
}

LocalIpcServer::~LocalIpcServer() noexcept { close_all(); }

void LocalIpcServer::close_all() noexcept {
    if (signal_fd_ >= 0) { static_cast<void>(::close(signal_fd_)); signal_fd_ = -1; }
    if (listen_fd_ >= 0) { static_cast<void>(::close(listen_fd_)); listen_fd_ = -1; }
    // Never unlink a different filesystem object (e.g. one replaced by a peer).
    // An unexpected surviving socket is intentionally left for an operator.
    if (!socket_path_.empty() && directory_fd_ >= 0) {
        struct stat path_info{};
        if (::fstatat(directory_fd_, "manager.sock", &path_info, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISSOCK(path_info.st_mode) && path_info.st_dev == socket_device_ &&
            path_info.st_ino == socket_inode_) {
            static_cast<void>(::unlinkat(directory_fd_, "manager.sock", 0));
        }
    }
    socket_path_.clear();
    if (directory_fd_ >= 0) { static_cast<void>(::close(directory_fd_)); directory_fd_ = -1; }
}

bool LocalIpcServer::open(std::string_view directory, const sigset_t& blocked_signals) noexcept {
    if (listen_fd_ >= 0 || signal_fd_ >= 0 || directory_fd_ >= 0 || !valid_directory(directory)) {
        return false;
    }
    // Explicit opt-in path, with an existing private directory (0700).
    // Never create or delete a directory, and never remove an existing socket.
    const std::string full = std::string(directory) + "/manager.sock";
    if (full.size() >= sizeof(sockaddr_un::sun_path)) { return false; }
    const std::string name(directory);
    const int dir_fd = ::open(name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir_fd < 0) { return false; }
    directory_fd_ = dir_fd;
    struct stat st{};
    if (::fstat(directory_fd_, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != ::geteuid() || (st.st_mode & 0777U) != 0700U) {
        close_all();
        return false;
    }
    // A preexisting entry is an error, including an orphan from a crash.
    struct stat existing{};
    if (::fstatat(directory_fd_, "manager.sock", &existing, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        close_all();
        return false;
    }
    // Signal readiness is mandatory before publishing manager_ready. If this
    // kernel object cannot be obtained, startup fails before binding.
    signal_fd_ = ::signalfd(-1, &blocked_signals, SFD_CLOEXEC | SFD_NONBLOCK);
    if (signal_fd_ < 0) { close_all(); return false; }
    const int listener = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0) { close_all(); return false; }
    listen_fd_ = listener;
    struct sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, full.c_str(), full.size() + 1);
    // Parent directory denies everyone except the service user. umask adds
    // defense-in-depth against group/world-readable socket creation.
    const mode_t old_umask = ::umask(0177);
    const int bound = ::bind(listen_fd_, reinterpret_cast<const sockaddr*>(&address),
        static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + full.size() + 1));
    ::umask(old_umask);
    if (bound != 0) { close_all(); return false; }
    socket_path_ = full;
    struct stat created{};
    if (::fstatat(directory_fd_, "manager.sock", &created, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISSOCK(created.st_mode)) { close_all(); return false; }
    socket_device_ = created.st_dev;
    socket_inode_ = created.st_ino;
    if ((created.st_mode & 0777U) != 0600U ||
        ::listen(listen_fd_, 8) != 0) { close_all(); return false; }
    return true;
}

void LocalIpcServer::handle_client(int client, const Lifecycle& lifecycle,
    HealthTracker& health, AuditLog& audit) noexcept {
    // Authenticate before reading untrusted bytes; operation authorization
    // follows strict framing. No administrative action is permitted.
    struct ucred peer{};
    socklen_t length = sizeof(peer);
    const bool identified = ::getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &length) == 0 &&
        length == sizeof(peer) && peer.pid > 0;
    const auto actor = identified ? std::optional<AuditActor>{{peer.pid, peer.uid, peer.gid}} : std::nullopt;
    if (!identified || !authorize_local_peer(peer.uid, peer.gid, ::geteuid(), ::getegid(),
                              IpcAction::Status)) {
        health.record(HealthError::Rejected);
        static_cast<void>(audit.record(AuditEvent::AuthenticationFailed, actor));
        return;
    }
    const auto report = [&](HealthError error, AuditEvent event) {
        health.record(error);
        static_cast<void>(audit.record(event, actor));
    };

    std::array<char, 4> header{};
    if (!read_exact(client, header.data(), header.size())) {
        report(HealthError::Transport, AuditEvent::TransportFailed);
        return;
    }
    const auto size = (static_cast<std::uint32_t>(static_cast<unsigned char>(header[0])) << 24U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(header[1])) << 16U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(header[2])) << 8U) |
        static_cast<std::uint32_t>(static_cast<unsigned char>(header[3]));
    if (size == 0 || size > max_frame_size) {
        report(HealthError::Rejected, AuditEvent::RequestRejected);
        return;
    }
    std::array<char, max_frame_size> request{};
    if (!read_exact(client, request.data(), size)) {
        report(HealthError::Transport, AuditEvent::TransportFailed);
        return;
    }
    const std::string_view payload(request.data(), size);
    const bool is_health = payload.starts_with(health_prefix);
    const auto operation_prefix = is_health ? health_prefix : prefix;
    const auto action = is_health ? IpcAction::Health : IpcAction::Status;
    constexpr std::string_view admin_prefix = "KSIPC/1 ADMIN ";
    if (payload.size() == admin_prefix.size() + 17 && payload.starts_with(admin_prefix) &&
        payload.back() == '\n' && hex_id(payload.substr(admin_prefix.size(), 16))) {
        report(HealthError::Rejected, AuditEvent::AdministrativeDenied);
        return;
    }
    if (payload.size() != operation_prefix.size() + 17 ||
        !payload.starts_with(operation_prefix) || payload.back() != '\n') {
        report(HealthError::Rejected, AuditEvent::RequestRejected);
        return;
    }
    const auto request_id = payload.substr(operation_prefix.size(), 16);
    if (!hex_id(request_id) ||
        !authorize_local_peer(peer.uid, peer.gid, ::geteuid(), ::getegid(), action)) {
        report(HealthError::Rejected, AuditEvent::RequestRejected);
        return;
    }
    // Commit the authorization decision before exposing any response.
    if (!audit.record(is_health ? AuditEvent::HealthAuthorized : AuditEvent::StatusAuthorized, actor)) {
        return;
    }
    if (is_health) {
        std::array<char, max_health_response_size> response{};
        const auto snapshot = health.sample(lifecycle.state());
        if ((!snapshot.usage.cpu_ms || !snapshot.usage.peak_rss_kib) &&
            !audit.record(AuditEvent::SamplingFailed, actor)) { return; }
        const auto count = encode_health(snapshot, request_id, response);
        if (count == 0) { report(HealthError::Sampling, AuditEvent::SamplingFailed); return; }
        if (!send_frame(client, std::string_view(response.data(), count), max_health_response_size)) {
            report(HealthError::Transport, AuditEvent::TransportFailed);
        }
        return;
    }
    // Preserve the M2.3 response and its original 64-byte bound.
    std::array<char, max_frame_size> response{};
    constexpr std::string_view start = "KSIPC/1 OK ";
    constexpr std::string_view end = " LIFECYCLE_ONLY\n";
    std::memcpy(response.data(), start.data(), start.size());
    std::memcpy(response.data() + start.size(), request_id.data(), request_id.size());
    std::memcpy(response.data() + start.size() + request_id.size(), end.data(), end.size());
    if (!send_frame(client, std::string_view(response.data(),
        start.size() + request_id.size() + end.size()), max_frame_size)) {
        report(HealthError::Transport, AuditEvent::TransportFailed);
    }
}

bool LocalIpcServer::serve(const Lifecycle& lifecycle, HealthTracker& health, AuditLog& audit) noexcept {
    if (listen_fd_ < 0 || signal_fd_ < 0) { return false; }
    bool stopped = false;
    for (;;) {
        std::array<struct pollfd, 2> ready{{
            {signal_fd_, POLLIN, 0}, {listen_fd_, POLLIN, 0}
        }};
        const int rc = ::poll(ready.data(), ready.size(), -1);
        if (rc < 0 && errno == EINTR) { continue; }
        if (rc <= 0 || (ready[0].revents & (POLLERR | POLLNVAL | POLLHUP)) != 0 ||
            (ready[1].revents & (POLLERR | POLLNVAL | POLLHUP)) != 0) { break; }
        // Always prioritize shutdown over accepting a pending client.
        if ((ready[0].revents & POLLIN) != 0) {
            struct signalfd_siginfo info{};
            if (::read(signal_fd_, &info, sizeof(info)) == sizeof(info) &&
                (info.ssi_signo == static_cast<std::uint32_t>(SIGTERM) ||
                 info.ssi_signo == static_cast<std::uint32_t>(SIGINT))) {
                stopped = true;
            }
            break;
        }
        if ((ready[1].revents & POLLIN) != 0) {
            const int client = ::accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (client >= 0) {
                handle_client(client, lifecycle, health, audit);
                static_cast<void>(::close(client));
                if (!audit.ok()) { break; }
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                break;
            }
        }
    }
    return stopped;
}
} // namespace knetsentry::service

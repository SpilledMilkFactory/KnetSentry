// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include "knetsentry/service/health.hpp"
#include "knetsentry/service/audit.hpp"
#include "knetsentry/service/event_query.hpp"

#include <csignal>
#include <string>
#include <string_view>
#include <sys/types.h>

namespace knetsentry::service {

// Authorization is separate from SO_PEERCRED channel authentication. The
// role matrix allows only same-UID/GID read-only STATUS, HEALTH, AGENTS and explicitly enabled EVENTS.
enum class IpcAction : unsigned char { Status, Administrative, Health, Agents, Events };
[[nodiscard]] bool authorize_local_peer(uid_t peer_uid, gid_t peer_gid,
    uid_t service_uid, gid_t service_gid, IpcAction action) noexcept;

// M2.3 / I-01: Linux-only, explicit opt-in, read-only operations.
// The complete socket directory must already exist and belong to the daemon
// user with mode 0700. No privileges, network sockets, or manager mutations.
class LocalIpcServer final {
public:
    LocalIpcServer() = default;
    ~LocalIpcServer() noexcept;
    LocalIpcServer(const LocalIpcServer&) = delete;
    LocalIpcServer& operator=(const LocalIpcServer&) = delete;
    LocalIpcServer(LocalIpcServer&&) = delete;
    LocalIpcServer& operator=(LocalIpcServer&&) = delete;

    [[nodiscard]] bool open(std::string_view directory, const sigset_t& blocked_signals) noexcept;
    // Explicit private registry; no initialization or mutation.
    [[nodiscard]] bool set_enrollment_directory(std::string_view directory) noexcept;
    [[nodiscard]] bool set_event_store(const storage::EventStore& store) noexcept;
    // SIGINT/SIGTERM must be blocked by the calling thread before this call.
    // Returns true only after a supported shutdown signal is consumed.
    [[nodiscard]] bool serve(const Lifecycle& lifecycle, HealthTracker& health, AuditLog& audit) noexcept;

private:
    void close_all() noexcept;
    void handle_client(int client, const Lifecycle& lifecycle, HealthTracker& health, AuditLog& audit) noexcept;

    const storage::EventStore* event_store_{};
    std::array<char, 32> event_session_{};
    int enrollment_fd_{-1};
    int listen_fd_{-1};
    int signal_fd_{-1};
    int directory_fd_{-1};
    std::string socket_path_{};
    dev_t socket_device_{};
    ino_t socket_inode_{};
};

} // namespace knetsentry::service

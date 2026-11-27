// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <sys/types.h>

namespace knetsentry::service {

enum class AuditEvent : std::uint8_t {
    Starting, Ready, Stopping, Stopped, Failed, ConfigDefault, ConfigValidated,
    ConfigRejected, IpcReady, IpcRejected, AuthenticationFailed, RequestRejected,
    AdministrativeDenied, StatusAuthorized, HealthAuthorized, TransportFailed,
    SamplingFailed, AgentsAuthorized, EventsAuthorized, AlertsAuthorized, AlertAcknowledgeAuthorized, AlertAcknowledged
};

struct AuditActor final {
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

// Single owner, synchronous, opt-in persistent sink. A disabled sink is not
// audit evidence. Once enabled, any failure is sticky and stops service.
class AuditLog final {
public:
    static constexpr std::uint64_t max_bytes = 1024U * 1024U;
    static constexpr std::size_t max_record = 512;
    AuditLog() = default;
    ~AuditLog() noexcept;
    AuditLog(const AuditLog&) = delete;
    AuditLog& operator=(const AuditLog&) = delete;
    [[nodiscard]] bool open(std::string_view directory) noexcept;
    [[nodiscard]] bool record(AuditEvent event,
        std::optional<AuditActor> actor = std::nullopt) noexcept;
    [[nodiscard]] bool ok() const noexcept { return !failed_; }
    [[nodiscard]] bool persistent() const noexcept { return fd_ >= 0 && !failed_; }
private:
    int fd_{-1};
    bool failed_{false};
    std::uint64_t sequence_{0};
    std::uint64_t bytes_{0};
    std::array<char, 33> session_{};
};

} // namespace knetsentry::service

// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <ostream>
#include <string_view>

namespace knetsentry::core {

// Only fixed catalog values may enter structured diagnostic metadata.
// These are application diagnostics, NOT a durable or privileged audit trail.
enum class DiagnosticLevel : std::uint8_t { Debug, Info, Warning, Error, Critical };
enum class DiagnosticComponent : std::uint8_t { Core, Desktop, Verification, Manager };
enum class DiagnosticEvent : std::uint8_t {
    GuiStarting, GuiReady, GuiLoadRejected, SelfTest, VerificationRejected,
    ManagerStarting, ManagerReady, ManagerStopping, ManagerStopped, ManagerFailed
};
enum class DiagnosticOutcome : std::uint8_t { Started, Success, Failure, Rejected };

// The referenced text is never formatted, persisted, copied or inspected by
// the logger. Only an explicit fixed [REDACTED] marker is emitted. Callers
// should avoid passing secrets at all unless reporting redaction is necessary.
struct SensitiveContext final {
    std::string_view text;
};

struct DiagnosticRecord final {
    DiagnosticLevel level{DiagnosticLevel::Info};
    DiagnosticComponent component{DiagnosticComponent::Core};
    DiagnosticEvent event{DiagnosticEvent::SelfTest};
    DiagnosticOutcome outcome{DiagnosticOutcome::Success};
    std::optional<std::uint64_t> count{};
    std::optional<SensitiveContext> sensitive_context{};
};

class DiagnosticLogger final {
public:
    static constexpr std::size_t max_record_bytes = 512;

    explicit DiagnosticLogger(std::ostream& output) noexcept : output_(output) {}
    DiagnosticLogger(const DiagnosticLogger&) = delete;
    DiagnosticLogger& operator=(const DiagnosticLogger&) = delete;

    // Never emits arbitrary strings, credentials, source identifiers, paths,
    // or network data. Fails explicitly on sink/format errors, never throws.
    // Thread-safe for callers sharing this logger instance. Per-instance
    // sequence numbers are diagnostic only, not cryptographic audit IDs.
    [[nodiscard]] bool write(const DiagnosticRecord& record) noexcept;

private:
    std::ostream& output_;
    std::mutex mutex_;
    std::uint64_t sequence_{0};
};

} // namespace knetsentry::core

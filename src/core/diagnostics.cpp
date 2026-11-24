// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/diagnostics.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <limits>
#include <string_view>

namespace knetsentry::core {
namespace {
// All strings in the output are compile-time allowlisted values. Unknown
// enum values fail closed as "unknown", rather than reflecting raw bytes.
constexpr const char* name(DiagnosticLevel value) noexcept {
    switch (value) {
    case DiagnosticLevel::Debug: return "debug";
    case DiagnosticLevel::Info: return "info";
    case DiagnosticLevel::Warning: return "warning";
    case DiagnosticLevel::Error: return "error";
    case DiagnosticLevel::Critical: return "critical";
    }
    return "unknown";
}
constexpr const char* name(DiagnosticComponent value) noexcept {
    switch (value) {
    case DiagnosticComponent::Core: return "core";
    case DiagnosticComponent::Desktop: return "desktop";
    case DiagnosticComponent::Verification: return "verification";
    case DiagnosticComponent::Manager: return "manager";
    }
    return "unknown";
}
constexpr const char* name(DiagnosticEvent value) noexcept {
    switch (value) {
    case DiagnosticEvent::GuiStarting: return "gui_starting";
    case DiagnosticEvent::GuiReady: return "gui_ready";
    case DiagnosticEvent::GuiLoadRejected: return "gui_load_rejected";
    case DiagnosticEvent::SelfTest: return "self_test";
    case DiagnosticEvent::VerificationRejected: return "verification_rejected";
    case DiagnosticEvent::ManagerStarting: return "manager_starting";
    case DiagnosticEvent::ManagerReady: return "manager_ready";
    case DiagnosticEvent::ManagerStopping: return "manager_stopping";
    case DiagnosticEvent::ManagerStopped: return "manager_stopped";
    case DiagnosticEvent::ManagerFailed: return "manager_failed";
    }
    return "unknown";
}
constexpr const char* name(DiagnosticOutcome value) noexcept {
    switch (value) {
    case DiagnosticOutcome::Started: return "started";
    case DiagnosticOutcome::Success: return "success";
    case DiagnosticOutcome::Failure: return "failure";
    case DiagnosticOutcome::Rejected: return "rejected";
    }
    return "unknown";
}
} // namespace

bool DiagnosticLogger::write(const DiagnosticRecord& record) noexcept {
    try {
        const std::lock_guard lock(mutex_);
        if (!output_.good() || sequence_ == std::numeric_limits<std::uint64_t>::max()) {
            return false;
        }
        // Reject corrupted/unknown enum values rather than accepting a
        // misleading record or reflecting any caller-controlled bytes.
        if (std::string_view(name(record.level)) == "unknown" ||
            std::string_view(name(record.component)) == "unknown" ||
            std::string_view(name(record.event)) == "unknown" ||
            std::string_view(name(record.outcome)) == "unknown") {
            return false;
        }
        const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const auto unix_ms = now < 0 ? 0ULL : static_cast<unsigned long long>(now);
        const auto next = static_cast<unsigned long long>(sequence_ + 1U);
        std::array<char, 32> count_buffer{};
        if (record.count) {
            const int count_size = std::snprintf(count_buffer.data(), count_buffer.size(),
                "%llu", static_cast<unsigned long long>(*record.count));
            if (count_size < 0 || static_cast<std::size_t>(count_size) >= count_buffer.size()) {
                return false;
            }
        }
        const char* count = record.count ? count_buffer.data() : "null";
        // Never interpolate or even read SensitiveContext::text. This is a
        // deny-by-construction boundary, not a fragile pattern-based filter.
        const char* detail = record.sensitive_context ? "\"[REDACTED]\"" : "null";
        std::array<char, max_record_bytes> bytes{};
        const int size = std::snprintf(bytes.data(), bytes.size(),
            "{\"schema\":1,\"time_unix_ms\":%llu,\"sequence\":%llu,"
            "\"level\":\"%s\",\"component\":\"%s\",\"event\":\"%s\","
            "\"outcome\":\"%s\",\"count\":%s,\"private_detail\":%s}\n",
            unix_ms, next, name(record.level), name(record.component),
            name(record.event), name(record.outcome), count, detail);
        if (size <= 0 || static_cast<std::size_t>(size) >= bytes.size()) {
            return false;
        }
        output_.write(bytes.data(), size);
        output_.flush();
        if (!output_.good()) {
            return false;
        }
        sequence_ += 1U;
        return true;
    } catch (...) {
        return false;
    }
}
} // namespace knetsentry::core

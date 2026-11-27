// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/detection/rule_schema.hpp>

namespace knetsentry::detection {
// One explicitly authorized store, endpoint binding and exact authentication unit.
// Receiver admission order/time, not source chronology or account identity.
enum class PatternStatus { Invalid, Unverified, Unavailable, Evaluated };
enum class AuthenticationPattern { RepeatedFailures, SuccessAfterFailures, UnspecifiedActivityFailure, InvalidUserObservation };
struct AuthenticationPolicy {
    static constexpr std::size_t max_threshold = 16;
    static constexpr std::uint64_t max_window_ms = 600000;
    std::size_t threshold{5};
    std::uint64_t window_ms{300000};
    bool operator==(const AuthenticationPolicy&) const = default;
};
struct AuthenticationFinding {
    AuthenticationPattern pattern;
    std::uint32_t version{1};
    RuleSeverity severity;
    Coverage coverage;
    std::vector<storage::EventId> evidence_ids; // Ordered, store-scoped; trigger is last.
    bool operator==(const AuthenticationFinding&) const = default;
};
struct AuthenticationReport {
    PatternStatus status{PatternStatus::Invalid};
    Coverage coverage{Coverage::Unknown};
    std::uint64_t revision{};
    AuthenticationPolicy policy;
    std::size_t observed{}, indeterminate{};
    std::vector<AuthenticationFinding> findings;
    bool operator==(const AuthenticationReport&) const = default;
};
// Stateless bounded snapshot scan. Caller establishes store authorization, trust and coverage.
// No partial results on failed/stale pages, pending index, or receiver clock regression.
// No finding is a confirmed compromise; allocation failures propagate.
[[nodiscard]] AuthenticationReport detect_authentication(const storage::EventStore& store,
    std::string_view binding, std::string_view unit, EvidenceTrust trust, Coverage coverage,
    AuthenticationPolicy policy = {});
} // namespace knetsentry::detection

// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/detection/rule_schema.hpp>

namespace knetsentry::detection {
// One rule, one authorized persistent store identity, one endpoint and exact unit.
struct SchedulePolicy {
    RuleDefinition rule;
    std::string store_identity; // Caller-assigned unique 64 lowercase hex digits; never reuse.
    std::string binding;
    std::uint64_t interval_ms{1000};
    std::uint64_t window_ms{60000};
    std::uint64_t suppression_ms{60000};
    std::size_t threshold{1};
    static constexpr std::uint64_t max_period_ms = 86400000;
    static constexpr std::size_t max_context = 16;
};
enum class ScheduleStatus { Invalid, Unverified, Disabled, NotDue, Unavailable, Evaluated, Replay };
struct ScheduledFinding {
    std::vector<storage::EventId> evidence_ids;
    std::uint64_t received_ms{};
    bool operator==(const ScheduledFinding&) const = default;
};
struct ScheduleReport {
    ScheduleStatus status{ScheduleStatus::Invalid};
    std::uint64_t generation{}, revision{};
    Coverage coverage{Coverage::Unknown};
    std::string rule_id, schedule_identity;
    std::uint32_t rule_version{};
    RuleSeverity severity{RuleSeverity::Unspecified};
    std::size_t observed{}, expired{}, suppressed{};
    std::vector<ScheduledFinding> findings;
};
// Explicit initialization only. Existing or abandoned state is never reset implicitly.
// Directory must be private, explicitly authorized, on a supported local filesystem.
[[nodiscard]] bool initialize_schedule(const SchedulePolicy& policy, std::string_view directory);
// Caller serializes store access, establishes trust, identity and coverage; supplies trusted receiver clock.
// No background work. Durable candidate batch is replayed until explicitly acknowledged.
[[nodiscard]] ScheduleReport run_schedule(const SchedulePolicy& policy, std::string_view directory,
    const storage::EventStore& store, std::uint64_t now_ms, bool enabled, EvidenceTrust trust, Coverage coverage);
// Acknowledge only after the caller has durably consumed the scoped generation.
// Does not authorize alert publication. Caller must reverify evidence before use.
[[nodiscard]] bool acknowledge_schedule(const SchedulePolicy& policy, std::string_view directory,
    std::uint64_t generation);
} // namespace knetsentry::detection

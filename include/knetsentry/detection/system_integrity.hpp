// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/detection/rule_schema.hpp>

namespace knetsentry::detection {
// Immutable, versioned Audit record-type rules, not OCSF outcome predicates.
struct SystemRule {
    std::string_view id;
    std::uint32_t version;
    std::uint64_t audit_type;
    RuleSeverity severity;
};
[[nodiscard]] std::span<const SystemRule> system_rules() noexcept;
enum class SystemDetectionStatus { Invalid, Unverified, Unavailable, Evaluated };
struct SystemFinding {
    std::string rule_id;
    std::uint32_t rule_version{};
    RuleSeverity severity{RuleSeverity::Unspecified};
    Coverage coverage{Coverage::Unknown};
    storage::EventId evidence_id{};
    std::uint64_t audit_type{};
    bool operator==(const SystemFinding&) const = default;
};
struct SystemDetectionReport {
    SystemDetectionStatus status{SystemDetectionStatus::Invalid};
    Coverage coverage{Coverage::Unknown};
    std::uint64_t revision{};
    std::size_t observed{}, unmatched{};
    std::vector<SystemFinding> findings;
    bool operator==(const SystemDetectionReport&) const = default;
};
// Caller establishes authorization, store identity, trust and coverage. No raw
// payload access, writes, live alert publication or inference of audit outcome.
[[nodiscard]] SystemDetectionReport detect_system_integrity(const storage::EventStore& store,
    std::string_view binding, EvidenceTrust trust, Coverage coverage);
} // namespace knetsentry::detection

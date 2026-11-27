// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/storage/event_store.hpp>
#include <span>

namespace knetsentry::detection {
// Caller-provided provenance, not a claim that endpoint observations are true.
enum class EvidenceTrust { Unverified, VerifiedStored };
enum class Coverage { Unknown, Partial, SourceObserved };
enum class EvaluationStatus { Invalid, Unverified, Unsupported, NoRules, Evaluated };
struct Rule {
    std::string id;
    std::uint32_t version{};
    std::optional<agent::OcsfActivity> activity;
    std::optional<agent::OcsfStatus> outcome;
    std::string source_unit; // Empty = any supported authentication source; otherwise exact.
};
struct Finding {
    std::string rule_id;
    std::uint32_t rule_version{};
    storage::EventId evidence_id{}; // Scoped to the caller's selected store.
    Coverage coverage{Coverage::Unknown};
    bool operator==(const Finding&) const = default;
};
struct Evaluation {
    EvaluationStatus status{EvaluationStatus::Invalid};
    Coverage coverage{Coverage::Unknown};
    std::size_t evaluated{}, indeterminate{};
    std::vector<Finding> findings;
    bool operator==(const Evaluation&) const = default;
};
// Immutable configuration, single-event evaluation. No IO, clock, response or alert authority.
// Allocation failure propagates; a caller must not interpret it as a negative detection.
class Engine final {
public:
    static constexpr std::size_t max_rules = 64;
    static constexpr std::size_t max_rule_id = 64;
    [[nodiscard]] static std::optional<Engine> create(std::span<const Rule> rules);
    [[nodiscard]] Evaluation evaluate(const storage::EventSummary& event,
        EvidenceTrust trust, Coverage coverage) const;
private:
    explicit Engine(std::vector<Rule> rules);
    std::vector<Rule> rules_;
};
} // namespace knetsentry::detection

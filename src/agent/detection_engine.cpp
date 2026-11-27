// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/rule_schema.hpp>
#include <knetsentry/agent/authentication.hpp>
#include <algorithm>
#include <limits>
#include <utility>

namespace knetsentry::detection {
namespace {
using A = agent::OcsfActivity;
using S = agent::OcsfStatus;
using C = agent::OcsfClass;
using G = agent::OcsfCategory;
using M = agent::MappingResult;
using J = agent::JournalMode;
using E = agent::AuthEvent;
constexpr auto max_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
constexpr auto max_source_ms = ((std::uint64_t{1} << 55) - 1) / 1000;
bool valid_classified(const storage::EventSummary& event) noexcept {
    const auto allowed = [&](E category) { return agent::valid_auth_event(event.source_unit, category); };
    if (event.activity_id == A::Logon && event.status_id == S::Success) { return allowed(E::SshAccepted); }
    if (event.activity_id == A::Logon && event.status_id == S::Failure) { return allowed(E::SshFailed) || allowed(E::LoginFailed); }
    if (event.activity_id == A::Unknown && event.status_id == S::Failure) { return allowed(E::AuthenticationFailed); }
    if (event.activity_id == A::Unknown && event.status_id == S::Unknown) { return allowed(E::SshInvalidUser); }
    if (event.activity_id == A::Logon && event.status_id == S::Unknown) { return allowed(E::SessionOpened) || allowed(E::LoginSessionCreated); }
    if (event.activity_id == A::Logoff && event.status_id == S::Unknown) { return allowed(E::SessionClosed) || allowed(E::LoginSessionRemoved); }
    return false;
}
bool valid_event(const storage::EventSummary& event) noexcept {
    if (event.id == 0 || event.id > max_id || event.received_ms == 0 || event.received_ms > max_id ||
        event.time_ms > max_source_ms || event.severity != agent::OcsfSeverity::Unknown) { return false; }
    if (event.mapping == M::Classified) {
        return event.class_uid == C::Authentication && event.category == G::IdentityAndAccessManagement &&
            event.source_mode == J::Authentication && valid_classified(event);
    }
    if (event.class_uid != C::Base || event.category != G::Unknown || event.activity_id != A::Unknown ||
        event.status_id != S::Unknown) { return false; }
    if (event.mapping == M::MetadataOnly) { return event.source_mode == J::Metadata && agent::valid_journal_unit(event.source_unit); }
    if (event.mapping == M::AuditTypeUnmapped) { return event.source_mode == J::Audit && event.source_unit == "audit"; }
    return (event.mapping == M::Redacted || event.mapping == M::Unclassified) &&
        event.source_mode == J::Authentication && agent::valid_auth_unit(event.source_unit);
}
} // namespace
Engine::Engine(std::vector<Rule> rules) : rules_(std::move(rules)) {}
std::optional<Engine> Engine::create(std::span<const Rule> rules) {
    if (rules.size() > max_rules || !std::ranges::all_of(rules, [](const Rule& rule) { return validate_predicate(rule) == RuleError::None; })) { return std::nullopt; }
    std::vector<Rule> owned(rules.begin(), rules.end());
    std::ranges::sort(owned, {}, &Rule::id);
    if (std::ranges::adjacent_find(owned, [](const Rule& lhs, const Rule& rhs) { return lhs.id == rhs.id; }) != owned.end()) {
        return std::nullopt;
    }
    return Engine(std::move(owned));
}
Evaluation Engine::evaluate(const storage::EventSummary& event, EvidenceTrust trust, Coverage coverage) const {
    Evaluation result;
    if ((trust != EvidenceTrust::Unverified && trust != EvidenceTrust::VerifiedStored) ||
        (coverage != Coverage::Unknown && coverage != Coverage::Partial && coverage != Coverage::SourceObserved) ||
        !valid_event(event)) { return result; }
    result.coverage = coverage;
    if (trust != EvidenceTrust::VerifiedStored) { result.status = EvaluationStatus::Unverified; return result; }
    if (event.mapping != M::Classified) { result.status = EvaluationStatus::Unsupported; return result; }
    if (rules_.empty()) { result.status = EvaluationStatus::NoRules; return result; }
    result.status = EvaluationStatus::Evaluated;
    for (const auto& rule : rules_) {
        // A known mismatch dominates an unknown field in the conjunction.
        if ((!rule.source_unit.empty() && rule.source_unit != event.source_unit) ||
            (rule.activity && event.activity_id != A::Unknown && *rule.activity != event.activity_id) ||
            (rule.outcome && event.status_id != S::Unknown && *rule.outcome != event.status_id)) {
            ++result.evaluated;
            continue;
        }
        if ((rule.activity && event.activity_id == A::Unknown) || (rule.outcome && event.status_id == S::Unknown)) {
            ++result.indeterminate;
            continue;
        }
        ++result.evaluated;
        result.findings.push_back({rule.id, rule.version, event.id, coverage});
    }
    return result;
}
} // namespace knetsentry::detection

// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/authentication_patterns.hpp>
#include <knetsentry/agent/authentication.hpp>
#include <algorithm>
#include <array>
#include <utility>

namespace knetsentry::detection {
namespace {
using A = agent::OcsfActivity;
using S = agent::OcsfStatus;
using J = agent::JournalMode;
using P = AuthenticationPattern;
using storage::StoreStatus;
struct Failure {
    storage::EventId id;
    std::uint64_t received_ms;
};
RuleDefinition definition(std::string id, std::optional<A> activity, S outcome,
    std::string_view unit, RuleSeverity severity) {
    RuleDefinition result;
    result.schema_version = ValidatedRuleSet::schema_version;
    result.ocsf_version = agent::NormalizedEvent::schema_version;
    result.mapping_revision = agent::NormalizedEvent::mapping_revision;
    result.predicate = {std::move(id), 1, activity, outcome, std::string(unit)};
    result.title = "Authentication observation";
    result.description = "Reported observation, not proof of compromise.";
    result.severity = severity;
    result.source_mode = J::Authentication;
    return result;
}
AuthenticationReport refused(PatternStatus status) {
    AuthenticationReport result;
    result.status = status;
    return result;
}
bool matched(const Evaluation& evaluation, std::string_view id) {
    return std::ranges::any_of(evaluation.findings, [id](const Finding& finding) { return finding.rule_id == id; });
}
void emit(AuthenticationReport& report, P pattern, RuleSeverity severity,
    const std::vector<Failure>& failures, std::optional<storage::EventId> trigger) {
    AuthenticationFinding finding{pattern, 1, severity, report.coverage, {}};
    for (const auto& failure : failures) { finding.evidence_ids.push_back(failure.id); }
    if (trigger) { finding.evidence_ids.push_back(*trigger); }
    report.findings.push_back(std::move(finding));
}
} // namespace
AuthenticationReport detect_authentication(const storage::EventStore& store,
    std::string_view binding, std::string_view unit, EvidenceTrust trust, Coverage coverage,
    AuthenticationPolicy policy) {
    if (!agent::valid_delivery_binding(binding) || !agent::valid_auth_unit(unit) ||
        policy.threshold < 2 || policy.threshold > AuthenticationPolicy::max_threshold ||
        policy.window_ms == 0 || policy.window_ms > AuthenticationPolicy::max_window_ms ||
        (trust != EvidenceTrust::Unverified && trust != EvidenceTrust::VerifiedStored) ||
        (coverage != Coverage::Unknown && coverage != Coverage::Partial && coverage != Coverage::SourceObserved)) { return {}; }
    if (trust != EvidenceTrust::VerifiedStored) { return refused(PatternStatus::Unverified); }
    // Only activate predicates reachable on this exact source. All supported sources
    // need not support successful logons or definite failures under mapping revision 1.
    const std::array candidates{
        definition("failure", A::Logon, S::Failure, unit, RuleSeverity::Medium),
        definition("success", A::Logon, S::Success, unit, RuleSeverity::High),
        definition("any-failure", std::nullopt, S::Failure, unit, RuleSeverity::Low)};
    std::vector<RuleDefinition> definitions;
    for (const auto& candidate : candidates) {
        const auto checked = ValidatedRuleSet::compile(std::span(&candidate, 1));
        if (checked.rules) { definitions.push_back(candidate); }
        else if (checked.diagnostics.size() != 1 || checked.diagnostics.front().code != RuleError::UnreachableCondition) { return {}; }
    }
    const auto compiled = ValidatedRuleSet::compile(definitions);
    if (!compiled.rules) { return {}; }
    AuthenticationReport report;
    report.status = PatternStatus::Evaluated;
    report.coverage = coverage;
    report.policy = policy;
    storage::SearchQuery query;
    query.binding = binding;
    query.source_unit = unit;
    query.source_mode = J::Authentication;
    query.limit = storage::EventStore::max_page;
    std::vector<Failure> failures;
    std::uint64_t previous_ms{};
    // Current storage contract caps records at 128, hence at most four pages.
    constexpr auto max_pages = storage::StoragePolicy::record_ceiling / storage::EventStore::max_page;
    for (std::size_t page_number = 0; page_number < max_pages; ++page_number) {
        const auto page = store.search(query);
        if (page.status != StoreStatus::Ok || (query.revision && page.revision != *query.revision) ||
            page.events.size() > query.limit || (page.more && page.events.empty())) { return refused(PatternStatus::Unavailable); }
        query.revision = page.revision;
        report.revision = page.revision;
        for (const auto& event : page.events) {
            if (event.id <= query.after || event.source_unit != unit || event.source_mode != J::Authentication ||
                event.received_ms < previous_ms) { return refused(PatternStatus::Invalid); }
            const auto evaluation = compiled.rules->engine().evaluate(event, trust, coverage);
            if (evaluation.status != EvaluationStatus::Evaluated && evaluation.status != EvaluationStatus::Unsupported &&
                evaluation.status != EvaluationStatus::NoRules) { return refused(PatternStatus::Invalid); }
            query.after = event.id;
            previous_ms = event.received_ms;
            ++report.observed;
            std::erase_if(failures, [&](const Failure& failure) { return event.received_ms - failure.received_ms > policy.window_ms; });
            if (matched(evaluation, "failure")) {
                const bool crossing = failures.size() < policy.threshold;
                if (!crossing) { failures.erase(failures.begin()); }
                failures.push_back({event.id, event.received_ms});
                if (crossing && failures.size() == policy.threshold) {
                    emit(report, P::RepeatedFailures, RuleSeverity::Medium, failures, std::nullopt);
                }
            } else if (matched(evaluation, "success")) {
                if (failures.size() == policy.threshold && event.received_ms > failures.back().received_ms) {
                    emit(report, P::SuccessAfterFailures, RuleSeverity::High, failures, event.id);
                }
                failures.clear();
            } else {
                if (matched(evaluation, "any-failure") && event.activity_id == A::Unknown) {
                    emit(report, P::UnspecifiedActivityFailure, RuleSeverity::Low, {}, event.id);
                } else if (evaluation.status == EvaluationStatus::Evaluated &&
                    event.activity_id == A::Unknown && event.status_id == S::Unknown) {
                    // Mapping revision 1 has exactly one classified observation with both fields
                    // unknown: SSH invalid-user. This is not a completed authentication failure.
                    emit(report, P::InvalidUserObservation, RuleSeverity::Low, {}, event.id);
                }
                if (evaluation.status != EvaluationStatus::Evaluated || event.activity_id == A::Unknown || event.status_id == S::Unknown) {
                    ++report.indeterminate;
                }
                // Unknown, redacted or unrelated observations break the sequence.
                failures.clear();
            }
        }
        if (!page.more) {
            const auto pending = store.pending(0, query.revision, 1);
            if (pending.status != StoreStatus::Ok || pending.revision != page.revision || pending.more || !pending.ids.empty()) {
                return refused(PatternStatus::Unavailable);
            }
            return report;
        }
    }
    return refused(PatternStatus::Unavailable);
}
} // namespace knetsentry::detection

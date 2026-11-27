// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/rule_schema.hpp>
#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <utility>

namespace {
using namespace knetsentry::detection;
using namespace knetsentry::agent;
using namespace knetsentry::storage;
void require(bool condition, const char* message) {
    if (!condition) { throw std::runtime_error(message); }
}
RuleDefinition fixture() {
    RuleDefinition definition;
    definition.schema_version = 1;
    definition.ocsf_version = "1.4.0";
    definition.mapping_revision = 1;
    definition.predicate = Rule{"ssh-failure", 2, OcsfActivity::Logon, OcsfStatus::Failure, "ssh.service"};
    definition.title = "Failed SSH logon";
    definition.description = "One reported failed logon; not proof of an incident.";
    definition.severity = RuleSeverity::High;
    definition.source_mode = JournalMode::Authentication;
    return definition;
}
template<class Change> void reject(Change change, RuleError expected) {
    std::array definitions{fixture()};
    change(definitions.front());
    const auto result = ValidatedRuleSet::compile(definitions);
    require(!result.rules && result.diagnostics.size() == 1, "invalid definition accepted");
    const auto& diagnostic = result.diagnostics.front();
    require(diagnostic.rule_index == 0 && diagnostic.code == expected, "incorrect diagnostic");
    const auto text = describe(diagnostic.code);
    require(!text.field.empty() && !text.action.empty(), "missing diagnostic guidance");
}
void invalid_definitions() {
    reject([](auto& d) { d.schema_version = 2; }, RuleError::UnsupportedSchema);
    reject([](auto& d) { d.ocsf_version = "1.5.0"; }, RuleError::UnsupportedOcsf);
    reject([](auto& d) { d.mapping_revision = 0; }, RuleError::UnsupportedMapping);
    reject([](auto& d) { d.title.clear(); }, RuleError::InvalidTitle);
    reject([](auto& d) { d.title.assign(97, 'a'); }, RuleError::InvalidTitle);
    reject([](auto& d) { d.title = " bad"; }, RuleError::InvalidTitle);
    reject([](auto& d) { d.description = "bad\nline"; }, RuleError::InvalidDescription);
    reject([](auto& d) { d.description.assign(513, 'a'); }, RuleError::InvalidDescription);
    reject([](auto& d) { d.description = std::string("a\0b", 3); }, RuleError::InvalidDescription);
    reject([](auto& d) { d.description.clear(); }, RuleError::InvalidDescription);
    reject([](auto& d) { d.title = "\xC3\xA9"; }, RuleError::InvalidTitle);
    reject([](auto& d) { d.severity = RuleSeverity::Unspecified; }, RuleError::UnsupportedSeverity);
    reject([](auto& d) { d.source_mode = JournalMode::Audit; }, RuleError::UnsupportedSourceMode);
    reject([](auto& d) { d.predicate.id = "Upper"; }, RuleError::InvalidId);
    reject([](auto& d) { d.predicate.id.clear(); }, RuleError::InvalidId);
    reject([](auto& d) { d.predicate.id.assign(65, 'a'); }, RuleError::InvalidId);
    reject([](auto& d) { d.predicate.version = 0; }, RuleError::InvalidVersion);
    reject([](auto& d) { d.predicate.activity.reset(); d.predicate.outcome.reset(); }, RuleError::MissingCondition);
    reject([](auto& d) { d.predicate.activity = OcsfActivity::Unknown; }, RuleError::UnsupportedActivity);
    reject([](auto& d) { d.predicate.outcome = OcsfStatus::Unknown; }, RuleError::UnsupportedOutcome);
    reject([](auto& d) { d.predicate.source_unit = "ssh@*.service"; }, RuleError::UnsupportedSource);
    reject([](auto& d) { d.predicate.source_unit = "systemd-journald.service"; }, RuleError::UnsupportedSource);
    reject([](auto& d) { d.predicate.activity = OcsfActivity::Logoff; }, RuleError::UnreachableCondition);
    reject([](auto& d) { d.predicate.source_unit = "systemd-logind.service"; }, RuleError::UnreachableCondition);
    reject([](auto& d) { d.predicate.outcome = OcsfStatus::Success; d.predicate.source_unit = "login.service"; }, RuleError::UnreachableCondition);
    std::array definitions{fixture(), fixture(), fixture()};
    definitions[1].predicate.version = 3;
    definitions[2].predicate.id = "distinct";
    definitions[2].title.clear();
    const auto result = ValidatedRuleSet::compile(definitions);
    require(!result.rules && result.diagnostics.size() == 2, "partial activation or missing diagnostics");
    require(result.diagnostics[0].rule_index == 1 && result.diagnostics[0].code == RuleError::DuplicateId &&
        result.diagnostics[1].rule_index == 2 && result.diagnostics[1].code == RuleError::InvalidTitle, "diagnostic order");
    std::cout << "M7.2 schema versions, metadata, predicates, source requirements and actionable diagnostics: PASS\n";
}
void composition() {
    std::array definitions{fixture(), fixture()};
    definitions[1].predicate.id = "all-failure";
    definitions[1].predicate.activity.reset();
    definitions[1].predicate.source_unit.clear();
    definitions[1].severity = RuleSeverity::Low;
    const auto result = ValidatedRuleSet::compile(definitions);
    require(result.rules.has_value() && result.diagnostics.empty(), "valid rules refused");
    const auto& compiled = *result.rules;
    require(compiled.definitions().size() == 2, "metadata count");
    require(compiled.definitions()[0].predicate.id == "all-failure" && compiled.definitions()[1].severity == RuleSeverity::High, "metadata ordering");
    std::ranges::reverse(definitions);
    const auto reversed = ValidatedRuleSet::compile(definitions);
    require(reversed.rules.has_value(), "reversed configuration refused");
    definitions[0].title.clear();
    definitions[1].predicate.id = "changed";
    require(compiled.definitions()[1].predicate.id == "ssh-failure" && compiled.definitions()[0].title == "Failed SSH logon", "configuration not owned");
    MemoryEventStore store;
    const std::string binding = std::string(32, 'a') + std::string(64, 'b');
    const std::string row = "one\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + "\tssh.service\tssh-failed\n";
    const auto admission = store.append({binding, "ssh.service", row, JournalMode::Authentication, 1795000000999ULL});
    require(admission.status == StoreStatus::Ok && store.index(admission.id).status == StoreStatus::Ok, "fixture storage");
    const auto page = store.search({});
    require(page.status == StoreStatus::Ok && page.events.size() == 1, "fixture search");
    const auto& event = page.events.front();
    const auto evaluation = compiled.engine().evaluate(event, EvidenceTrust::VerifiedStored, Coverage::Partial);
    const auto repeat = reversed.rules->engine().evaluate(event, EvidenceTrust::VerifiedStored, Coverage::Partial);
    require(evaluation == repeat && evaluation.status == EvaluationStatus::Evaluated && evaluation.findings.size() == 2, "compiled evaluation");
    require(evaluation.findings[0].rule_id == "all-failure" && evaluation.findings[1].rule_id == "ssh-failure" &&
        evaluation.findings[1].rule_version == 2 && evaluation.findings[1].evidence_id == admission.id &&
        evaluation.findings[1].coverage == Coverage::Partial, "finding metadata linkage");
    const auto unverified = compiled.engine().evaluate(event, EvidenceTrust::Unverified, Coverage::Partial);
    require(unverified.status == EvaluationStatus::Unverified && unverified.findings.empty(), "trust bypass");
    const auto after = store.search({});
    require(after.revision == page.revision && event.severity == OcsfSeverity::Unknown && after.events.size() == 1 &&
        after.events.front().severity == OcsfSeverity::Unknown, "rule severity changed evidence");
    const auto empty = ValidatedRuleSet::compile({});
    require(empty.rules.has_value() && empty.diagnostics.empty(), "empty rule set");
    const auto no_rules = empty.rules->engine().evaluate(event, EvidenceTrust::VerifiedStored, Coverage::Unknown);
    require(no_rules.status == EvaluationStatus::NoRules, "empty activation semantics");
    std::vector<RuleDefinition> maximum;
    for (std::size_t i = 0; i < Engine::max_rules; ++i) {
        auto definition = fixture();
        definition.predicate.id = std::string(62, 'a') + (i < 10 ? "0" : "") + std::to_string(i);
        definition.title.assign(96, 'a');
        definition.description.assign(512, 'b');
        maximum.push_back(std::move(definition));
    }
    const auto bounded = ValidatedRuleSet::compile(maximum);
    require(bounded.rules.has_value() && bounded.diagnostics.empty(), "maximum valid set refused");
    const auto fanout = bounded.rules->engine().evaluate(event, EvidenceTrust::VerifiedStored, Coverage::Partial);
    require(fanout.findings.size() == Engine::max_rules, "maximum fanout");
    maximum.push_back(fixture());
    const auto overflow = ValidatedRuleSet::compile(maximum);
    require(!overflow.rules && overflow.diagnostics.size() == 1 && !overflow.diagnostics.front().rule_index &&
        overflow.diagnostics.front().code == RuleError::TooManyRules, "whole-set capacity diagnostic");
    std::cout << "M7.2 atomic compilation, owned metadata, deterministic engine and bounded activation: PASS\n";
}
} // namespace
int main() {
    try { invalid_definitions(); composition(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}

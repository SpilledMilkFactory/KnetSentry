// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/rule_schema.hpp>
#include <knetsentry/agent/authentication.hpp>
#include <algorithm>
#include <array>
#include <utility>

namespace knetsentry::detection {
namespace {
using A = agent::OcsfActivity;
using S = agent::OcsfStatus;
using E = agent::AuthEvent;
bool valid_id(std::string_view id) noexcept {
    return !id.empty() && id.size() <= Engine::max_rule_id && std::ranges::all_of(id, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
    });
}
bool valid_text(std::string_view value, std::size_t limit) noexcept {
    return !value.empty() && value.size() <= limit && value.front() != ' ' && value.back() != ' ' &&
        std::ranges::all_of(value, [](char c) { return c >= ' ' && c <= '~'; });
}
bool valid_severity(RuleSeverity severity) noexcept {
    return severity == RuleSeverity::Informational || severity == RuleSeverity::Low ||
        severity == RuleSeverity::Medium || severity == RuleSeverity::High || severity == RuleSeverity::Critical;
}
// Mapping revision 1: only definite matches are considered reachable. Unknown
// observations still retain their existing three-valued semantics at runtime.
struct Mapping { E event; A activity; S outcome; };
constexpr std::array mappings{
    Mapping{E::SshAccepted, A::Logon, S::Success},
    Mapping{E::SshFailed, A::Logon, S::Failure},
    Mapping{E::LoginFailed, A::Logon, S::Failure},
    Mapping{E::AuthenticationFailed, A::Unknown, S::Failure},
    Mapping{E::SshInvalidUser, A::Unknown, S::Unknown},
    Mapping{E::SessionOpened, A::Logon, S::Unknown},
    Mapping{E::LoginSessionCreated, A::Logon, S::Unknown},
    Mapping{E::SessionClosed, A::Logoff, S::Unknown},
    Mapping{E::LoginSessionRemoved, A::Logoff, S::Unknown}};
bool reachable(const Rule& rule) noexcept {
    return std::ranges::any_of(mappings, [&](const Mapping& mapping) {
        return (!rule.activity || *rule.activity == mapping.activity) &&
            (!rule.outcome || *rule.outcome == mapping.outcome) &&
            (rule.source_unit.empty() || agent::valid_auth_event(rule.source_unit, mapping.event));
    });
}
RuleError validate_definition(const RuleDefinition& definition) noexcept {
    if (definition.schema_version != ValidatedRuleSet::schema_version) { return RuleError::UnsupportedSchema; }
    if (definition.ocsf_version != agent::NormalizedEvent::schema_version) { return RuleError::UnsupportedOcsf; }
    if (definition.mapping_revision != agent::NormalizedEvent::mapping_revision) { return RuleError::UnsupportedMapping; }
    if (!valid_text(definition.title, ValidatedRuleSet::max_title)) { return RuleError::InvalidTitle; }
    if (!valid_text(definition.description, ValidatedRuleSet::max_description)) { return RuleError::InvalidDescription; }
    if (!valid_severity(definition.severity)) { return RuleError::UnsupportedSeverity; }
    if (definition.source_mode != agent::JournalMode::Authentication) { return RuleError::UnsupportedSourceMode; }
    const auto error = validate_predicate(definition.predicate);
    if (error != RuleError::None) { return error; }
    return reachable(definition.predicate) ? RuleError::None : RuleError::UnreachableCondition;
}
} // namespace
RuleError validate_predicate(const Rule& rule) noexcept {
    if (!valid_id(rule.id)) { return RuleError::InvalidId; }
    if (rule.version == 0) { return RuleError::InvalidVersion; }
    if (!rule.activity && !rule.outcome) { return RuleError::MissingCondition; }
    if (rule.activity && *rule.activity != A::Logon && *rule.activity != A::Logoff) { return RuleError::UnsupportedActivity; }
    if (rule.outcome && *rule.outcome != S::Success && *rule.outcome != S::Failure) { return RuleError::UnsupportedOutcome; }
    if (!rule.source_unit.empty() && !agent::valid_auth_unit(rule.source_unit)) { return RuleError::UnsupportedSource; }
    return RuleError::None;
}
DiagnosticText describe(RuleError code) noexcept {
    switch (code) {
    case RuleError::None: return {"", "No validation error."};
    case RuleError::TooManyRules: return {"rules", "Supply at most 64 rules."};
    case RuleError::InvalidId: return {"predicate.id", "Use 1-64 lowercase ASCII letters, digits, dots, underscores or hyphens."};
    case RuleError::InvalidVersion: return {"predicate.version", "Supply a nonzero rule version."};
    case RuleError::MissingCondition: return {"predicate", "Select activity, outcome or both."};
    case RuleError::UnsupportedActivity: return {"predicate.activity", "Select Logon or Logoff, or omit the predicate."};
    case RuleError::UnsupportedOutcome: return {"predicate.outcome", "Select Success or Failure, or omit the predicate."};
    case RuleError::UnsupportedSource: return {"predicate.source_unit", "Select an exact supported authentication unit, or leave empty."};
    case RuleError::UnsupportedSchema: return {"schema_version", "Use rule schema version 1."};
    case RuleError::UnsupportedOcsf: return {"ocsf_version", "Use OCSF-aligned version 1.4.0."};
    case RuleError::UnsupportedMapping: return {"mapping_revision", "Use normalization mapping revision 1."};
    case RuleError::InvalidTitle: return {"title", "Supply 1-96 printable ASCII bytes without leading or trailing spaces."};
    case RuleError::InvalidDescription: return {"description", "Supply 1-512 printable ASCII bytes without leading or trailing spaces."};
    case RuleError::UnsupportedSeverity: return {"severity", "Select Informational, Low, Medium, High or Critical."};
    case RuleError::UnsupportedSourceMode: return {"source_mode", "Select Authentication; other source modes are unsupported."};
    case RuleError::UnreachableCondition: return {"predicate", "Choose a condition and source combination with a definite match in mapping revision 1."};
    case RuleError::DuplicateId: return {"predicate.id", "Use a unique rule ID regardless of version."};
    case RuleError::EngineRejected: return {"rules", "Engine refused the validated set; do not activate it."};
    }
    return {"rules", "Unsupported diagnostic; do not activate the set."};
}
ValidatedRuleSet::ValidatedRuleSet(std::vector<RuleDefinition> definitions, Engine engine)
    : definitions_(std::move(definitions)), engine_(std::move(engine)) {}
RuleCompilation ValidatedRuleSet::compile(std::span<const RuleDefinition> definitions) {
    RuleCompilation result;
    if (definitions.size() > Engine::max_rules) {
        result.diagnostics.push_back({std::nullopt, RuleError::TooManyRules});
        return result;
    }
    for (std::size_t i = 0; i < definitions.size(); ++i) {
        const auto& definition = definitions[i];
        const auto error = validate_definition(definition);
        if (error != RuleError::None) { result.diagnostics.push_back({i, error}); }
        if (valid_id(definition.predicate.id)) {
            for (std::size_t j = 0; j < i; ++j) {
                if (definitions[j].predicate.id == definition.predicate.id) {
                    result.diagnostics.push_back({i, RuleError::DuplicateId});
                    break;
                }
            }
        }
    }
    if (!result.diagnostics.empty()) { return result; }
    std::vector<RuleDefinition> owned(definitions.begin(), definitions.end());
    std::ranges::sort(owned, {}, [](const RuleDefinition& definition) -> const std::string& { return definition.predicate.id; });
    std::vector<Rule> predicates;
    predicates.reserve(owned.size());
    for (const auto& definition : owned) { predicates.push_back(definition.predicate); }
    auto engine = Engine::create(predicates);
    if (!engine) {
        result.diagnostics.push_back({std::nullopt, RuleError::EngineRejected});
        return result;
    }
    result.rules.emplace(ValidatedRuleSet(std::move(owned), std::move(*engine)));
    return result;
}
} // namespace knetsentry::detection

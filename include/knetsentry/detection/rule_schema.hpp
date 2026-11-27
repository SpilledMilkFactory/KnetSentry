// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/detection/engine.hpp>
#include <string_view>

namespace knetsentry::detection {
// Severity describes the rule author's priority, not observed event severity.
enum class RuleSeverity : std::uint32_t { Unspecified, Informational, Low, Medium, High, Critical };
struct RuleDefinition {
    std::uint32_t schema_version{};
    std::string ocsf_version;
    std::uint32_t mapping_revision{};
    Rule predicate;
    std::string title;
    std::string description;
    RuleSeverity severity{RuleSeverity::Unspecified};
    agent::JournalMode source_mode{agent::JournalMode::Metadata};
};
enum class RuleError {
    None, TooManyRules, InvalidId, InvalidVersion, MissingCondition,
    UnsupportedActivity, UnsupportedOutcome, UnsupportedSource,
    UnsupportedSchema, UnsupportedOcsf, UnsupportedMapping, InvalidTitle,
    InvalidDescription, UnsupportedSeverity, UnsupportedSourceMode,
    UnreachableCondition, DuplicateId, EngineRejected
};
struct RuleDiagnostic {
    std::optional<std::size_t> rule_index; // Original input position; null = whole set.
    RuleError code;
};
struct DiagnosticText {
    std::string_view field;
    std::string_view action;
};
[[nodiscard]] DiagnosticText describe(RuleError code) noexcept;
// Shared with the M7.1 low-level engine; validates the first failing predicate field.
[[nodiscard]] RuleError validate_predicate(const Rule& rule) noexcept;
struct RuleCompilation;
class ValidatedRuleSet final {
public:
    static constexpr std::uint32_t schema_version = 1;
    static constexpr std::size_t max_title = 96;
    static constexpr std::size_t max_description = 512;
    ValidatedRuleSet(ValidatedRuleSet&&) noexcept = default;
    ValidatedRuleSet(const ValidatedRuleSet&) = delete;
    ValidatedRuleSet& operator=(const ValidatedRuleSet&) = delete;
    ValidatedRuleSet& operator=(ValidatedRuleSet&&) = delete;
    // One diagnostic per invalid definition, plus duplicate diagnostics. No input text echoed.
    [[nodiscard]] static RuleCompilation compile(std::span<const RuleDefinition> definitions);
    [[nodiscard]] const std::vector<RuleDefinition>& definitions() const noexcept { return definitions_; }
    [[nodiscard]] const Engine& engine() const noexcept { return engine_; }
private:
    ValidatedRuleSet(std::vector<RuleDefinition> definitions, Engine engine);
    std::vector<RuleDefinition> definitions_;
    Engine engine_;
};
struct RuleCompilation {
    std::optional<ValidatedRuleSet> rules;
    std::vector<RuleDiagnostic> diagnostics;
};
} // namespace knetsentry::detection

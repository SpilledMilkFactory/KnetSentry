// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/detection/authentication_patterns.hpp>
#include <knetsentry/detection/system_integrity.hpp>

namespace knetsentry::detection {
// Rule-level investigation context only, never a technique occurrence or coverage claim.
// Catalog revision is independent of rule, OCSF and upstream object versions.
inline constexpr std::uint32_t technique_catalog_revision = 1;
inline constexpr std::string_view technique_reference_release = "Enterprise v20";
enum class TechniqueMappingStatus : std::uint64_t { UnknownRule, Unmapped, ContextOnly };
struct TechniqueAssociation {
    std::string_view id, name, object_version, reference_url, rationale, limitation;
};
struct TechniqueMapping {
    std::span<const TechniqueAssociation> associations;
    TechniqueMappingStatus status{TechniqueMappingStatus::UnknownRule};
};
// Returned views refer to immutable static storage. Unknown versions and identities
// never inherit mappings. Callers must establish finding authenticity independently.
[[nodiscard]] TechniqueMapping technique_mapping(AuthenticationPattern pattern, std::uint32_t version) noexcept;
[[nodiscard]] TechniqueMapping technique_mapping(std::string_view system_rule_id,
    std::uint32_t version, std::uint64_t audit_type) noexcept;
// No generic RuleDefinition, ScheduleReport or AlertSnapshot mapping: custom rule IDs
// are caller-controlled and do not prove equivalence to a built-in pattern.
} // namespace knetsentry::detection

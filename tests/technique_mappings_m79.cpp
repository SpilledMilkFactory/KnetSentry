// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/technique_mappings.hpp>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
using namespace knetsentry::detection;
using P = AuthenticationPattern;
using S = TechniqueMappingStatus;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
void check(TechniqueMapping mapping, S status, std::initializer_list<std::string_view> ids) {
    require(mapping.status == status && mapping.associations.size() == ids.size(), "mapping disposition/count");
    std::size_t i{};
    for (const auto id : ids) {
        const auto& entry = mapping.associations[i++];
        require(entry.id == id && !entry.rationale.empty() && !entry.limitation.empty(), "mapping identity/context");
        if (id == "T1110") {
            require(entry.name == "Brute Force" && entry.object_version == "2.8" &&
                entry.reference_url == "https://attack.mitre.org/versions/v20/techniques/T1110/", "Brute Force provenance");
        } else if (id == "T1078") {
            require(entry.name == "Valid Accounts" && entry.object_version == "3.0" &&
                entry.reference_url == "https://attack.mitre.org/versions/v20/techniques/T1078/", "Valid Accounts provenance");
        } else {
            require(id == "T1547.006" && entry.name == "Kernel Modules and Extensions" && entry.object_version == "1.4" &&
                entry.reference_url == "https://attack.mitre.org/versions/v20/techniques/T1547/006/", "module provenance");
        }
    }
}
void verify() {
    require(technique_catalog_revision == 1 && technique_reference_release == "Enterprise v20", "catalog revision");
    check(technique_mapping(P::RepeatedFailures, 1), S::ContextOnly, {"T1110"});
    check(technique_mapping(P::SuccessAfterFailures, 1), S::ContextOnly, {"T1110", "T1078"});
    check(technique_mapping(P::UnspecifiedActivityFailure, 1), S::Unmapped, {});
    check(technique_mapping(P::InvalidUserObservation, 1), S::Unmapped, {});
    // Independently exercise the current native numeric domain, without an
    // out-of-range enum cast or narrowing the untrusted input.
    check(technique_mapping_from_code(0, 1), S::ContextOnly, {"T1110"});
    check(technique_mapping_from_code(1, 1), S::ContextOnly, {"T1110", "T1078"});
    check(technique_mapping_from_code(2, 1), S::Unmapped, {});
    check(technique_mapping_from_code(3, 1), S::Unmapped, {});
    constexpr std::int64_t invalid_codes[] = {
        -1, 4, 999, 4294967296LL, 4294967297LL, -4294967296LL,
        std::numeric_limits<std::int64_t>::min(), std::numeric_limits<std::int64_t>::max()};
    for (const auto code : invalid_codes) {
        check(technique_mapping_from_code(code, 1), S::UnknownRule, {});
    }
    for (std::int64_t code = 0; code < 4; ++code) {
        check(technique_mapping_from_code(code, 0), S::UnknownRule, {});
        check(technique_mapping_from_code(code, 2), S::UnknownRule, {});
        check(technique_mapping_from_code(code, std::numeric_limits<std::uint32_t>::max()), S::UnknownRule, {});
    }
    for (const auto pattern : {P::RepeatedFailures, P::SuccessAfterFailures, P::UnspecifiedActivityFailure, P::InvalidUserObservation}) {
        check(technique_mapping(pattern, 0), S::UnknownRule, {});
        check(technique_mapping(pattern, 2), S::UnknownRule, {});
    }
    require(system_rules().size() == 18, "Audit catalog changed; review mappings");
    std::size_t mapped{};
    for (const auto& rule : system_rules()) {
        const auto result = technique_mapping(rule.id, rule.version, rule.audit_type);
        if (rule.id == "audit-kernel-module") {
            require(rule.audit_type == 1330 && rule.version == 1, "kernel rule identity");
            check(result, S::ContextOnly, {"T1547.006"}); ++mapped;
        } else { check(result, S::Unmapped, {}); }
        check(technique_mapping(rule.id, 2, rule.audit_type), S::UnknownRule, {});
        check(technique_mapping(rule.id, rule.version, 0), S::UnknownRule, {});
    }
    require(mapped == 1, "unexpected mapped count");
    check(technique_mapping("audit-kernel-module", 1, 1305), S::UnknownRule, {});
    check(technique_mapping("audit-config-change", 1, 1330), S::UnknownRule, {});
    check(technique_mapping("AUDIT-KERNEL-MODULE", 1, 1330), S::UnknownRule, {});
    check(technique_mapping("audit-kernel-module-extra", 1, 1330), S::UnknownRule, {});
    check(technique_mapping(std::string_view("audit-kernel-module\0x", 21), 1, 1330), S::UnknownRule, {});
    check(technique_mapping("", 1, 1330), S::UnknownRule, {});
    const std::string oversized(Engine::max_rule_id + 1, 'x');
    check(technique_mapping(oversized, 1, 1330), S::UnknownRule, {});
    const auto first = technique_mapping(P::SuccessAfterFailures, 1);
    const auto second = technique_mapping(P::SuccessAfterFailures, 1);
    require(first.associations.data() == second.associations.data(), "stable immutable catalog");
}
} // namespace
int main() {
    try { verify(); std::cout << "M7.9 versioned context-only technique mappings, abstention and provenance: PASS\n"; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}

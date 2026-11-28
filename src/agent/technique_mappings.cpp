// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/technique_mappings.hpp>
#include <array>

namespace knetsentry::detection {
namespace {
using Status = TechniqueMappingStatus;
constexpr TechniqueAssociation failures{
    "T1110", "Brute Force", "2.8", "https://attack.mitre.org/versions/v20/techniques/T1110/",
    "Repeated reported logon failures are consistent with attempts to obtain access.",
    "No account, origin, credential method or adversarial intent is established; benign failures are possible."};
constexpr std::array repeated{failures};
constexpr std::array success{
    TechniqueAssociation{"T1110", "Brute Force", "2.8", "https://attack.mitre.org/versions/v20/techniques/T1110/",
        "A reported successful logon after repeated failures merits investigation of credential attempts.",
        "Receiver order is not source chronology; the failures and success may involve unrelated users."},
    TechniqueAssociation{"T1078", "Valid Accounts", "3.0", "https://attack.mitre.org/versions/v20/techniques/T1078/",
        "A reported success following failures provides context for investigating possible account misuse.",
        "No account identity, credential theft, account misuse or causal relationship is established."}};
constexpr std::array kernel{
    TechniqueAssociation{"T1547.006", "Kernel Modules and Extensions", "1.4",
        "https://attack.mitre.org/versions/v20/techniques/T1547/006/",
        "A kernel-module Audit record type is relevant to investigations of module-related abuse.",
        "No module identity, operation outcome, boot persistence, privilege escalation or malicious activity is established."}};
constexpr TechniqueMapping unmapped{{}, Status::Unmapped};
} // namespace
TechniqueMapping technique_mapping(AuthenticationPattern pattern, std::uint32_t version) noexcept {
    if (version != 1) { return {}; }
    switch (pattern) {
    case AuthenticationPattern::RepeatedFailures: return {repeated, Status::ContextOnly};
    case AuthenticationPattern::SuccessAfterFailures: return {success, Status::ContextOnly};
    case AuthenticationPattern::UnspecifiedActivityFailure:
    case AuthenticationPattern::InvalidUserObservation: return unmapped;
    }
    return {};
}
TechniqueMapping technique_mapping(std::string_view id, std::uint32_t version, std::uint64_t audit_type) noexcept {
    if (id.empty() || id.size() > Engine::max_rule_id || version != 1) { return {}; }
    for (const auto& rule : system_rules()) {
        if (rule.id == id && rule.version == version && rule.audit_type == audit_type) {
            if (id == "audit-kernel-module" && audit_type == 1330) { return {kernel, Status::ContextOnly}; }
            return unmapped;
        }
    }
    return {};
}
} // namespace knetsentry::detection

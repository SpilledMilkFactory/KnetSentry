// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/system_integrity.hpp>
#include <algorithm>
#include <array>
#include <limits>

namespace knetsentry::detection {
namespace {
using S = RuleSeverity;
using storage::StoreStatus;
// Numeric Linux Audit ABI types; no libaudit dependency. Fixed exact matches,
// deliberately not ranges. Record type alone does not establish success.
constexpr std::array rules{
    SystemRule{"audit-service-start", 1, 1130, S::Informational},
    SystemRule{"audit-service-stop", 1, 1131, S::Informational},
    SystemRule{"audit-daemon-config", 1, 1203, S::Medium},
    SystemRule{"audit-config-change", 1, 1305, S::Medium},
    SystemRule{"audit-file-capabilities", 1, 1321, S::Medium},
    SystemRule{"audit-capset", 1, 1322, S::Medium},
    SystemRule{"audit-netfilter-config", 1, 1325, S::Medium},
    SystemRule{"audit-kernel-module", 1, 1330, S::Medium},
    SystemRule{"audit-mac-policy-load", 1, 1403, S::Medium},
    SystemRule{"audit-mac-status", 1, 1404, S::Medium},
    SystemRule{"audit-anomalous-link", 1, 1702, S::High},
    SystemRule{"audit-anomalous-create", 1, 1703, S::High},
    SystemRule{"audit-integrity-data", 1, 1800, S::Medium},
    SystemRule{"audit-integrity-metadata", 1, 1801, S::Medium},
    SystemRule{"audit-integrity-status", 1, 1802, S::Medium},
    SystemRule{"audit-integrity-pcr", 1, 1804, S::Medium},
    SystemRule{"audit-integrity-policy", 1, 1805, S::Medium},
    SystemRule{"audit-ima-policy", 1, 1807, S::Medium}};
static_assert(rules.size() <= Engine::max_rules);
static_assert([] {
    for (std::size_t i = 0; i < rules.size(); ++i) {
        if (rules[i].id.empty() || rules[i].id.size() > Engine::max_rule_id || rules[i].version == 0 ||
            rules[i].audit_type < 1000 || rules[i].audit_type > 65535) { return false; }
        for (std::size_t j = 0; j < i; ++j) {
            if (rules[i].id == rules[j].id || rules[i].audit_type == rules[j].audit_type) { return false; }
        }
    }
    return true;
}());
SystemDetectionReport refused(SystemDetectionStatus status) {
    SystemDetectionReport result;
    result.status = status;
    return result;
}
bool valid_summary(const storage::EventSummary& event) noexcept {
    constexpr auto max_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    constexpr auto max_source_ms = ((std::uint64_t{1} << 55) - 1) / 1000;
    return event.id > 0 && event.id <= max_id && event.received_ms > 0 && event.received_ms <= max_id &&
        event.time_ms <= max_source_ms && event.source_unit == "audit" && event.source_mode == agent::JournalMode::Audit &&
        event.mapping == agent::MappingResult::AuditTypeUnmapped && event.class_uid == agent::OcsfClass::Base &&
        event.activity_id == agent::OcsfActivity::Unknown && event.status_id == agent::OcsfStatus::Unknown &&
        event.category == agent::OcsfCategory::Unknown && event.severity == agent::OcsfSeverity::Unknown &&
        event.audit_type >= 1000 && event.audit_type <= 65535;
}
} // namespace
std::span<const SystemRule> system_rules() noexcept { return rules; }
SystemDetectionReport detect_system_integrity(const storage::EventStore& store,
    std::string_view binding, EvidenceTrust trust, Coverage coverage) {
    using D = SystemDetectionStatus;
    if (!agent::valid_delivery_binding(binding) ||
        (trust != EvidenceTrust::Unverified && trust != EvidenceTrust::VerifiedStored) ||
        (coverage != Coverage::Unknown && coverage != Coverage::Partial && coverage != Coverage::SourceObserved)) { return {}; }
    if (trust != EvidenceTrust::VerifiedStored) { return refused(D::Unverified); }
    SystemDetectionReport report;
    report.status = D::Evaluated;
    report.coverage = coverage;
    storage::SearchQuery query;
    query.binding = binding;
    query.source_unit = "audit";
    query.source_mode = agent::JournalMode::Audit;
    query.limit = storage::EventStore::max_page;
    constexpr auto max_pages = storage::StoragePolicy::record_ceiling / storage::EventStore::max_page;
    for (std::size_t i = 0; i < max_pages; ++i) {
        const auto page = store.search(query);
        if (page.status != StoreStatus::Ok || page.revision == 0 || (query.revision && page.revision != *query.revision) ||
            page.events.size() > query.limit || (page.more && page.events.size() != query.limit) ||
            (query.after != 0 && page.events.empty())) { return refused(D::Unavailable); }
        query.revision = page.revision;
        report.revision = page.revision;
        for (const auto& event : page.events) {
            if (event.id <= query.after || !valid_summary(event)) { return refused(D::Invalid); }
            query.after = event.id;
            ++report.observed;
            const auto rule = std::ranges::find(rules, event.audit_type, &SystemRule::audit_type);
            if (rule == rules.end()) { ++report.unmatched; continue; }
            report.findings.push_back({std::string(rule->id), rule->version, rule->severity, coverage, event.id, event.audit_type});
        }
        if (!page.more) {
            const auto pending = store.pending(0, query.revision, 1);
            if (pending.status != StoreStatus::Ok || pending.revision != page.revision || pending.more || !pending.ids.empty()) {
                return refused(D::Unavailable);
            }
            return report;
        }
    }
    return refused(D::Unavailable);
}
} // namespace knetsentry::detection

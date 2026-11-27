// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/system_integrity.hpp>
#include <iostream>
#include <stdexcept>

namespace {
using namespace knetsentry::detection;
using namespace knetsentry::storage;
using knetsentry::agent::JournalMode;
using D = SystemDetectionStatus;
void require(bool condition, const char* message) {
    if (!condition) { throw std::runtime_error(message); }
}
std::string binding(char marker = 'a') { return std::string(32, marker) + std::string(64, 'b'); }
EventId append(EventStore& store, unsigned n, unsigned type, char endpoint = 'a', bool index = true) {
    const auto row = "cursor" + std::to_string(n) + "\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + "\taudit\t" + std::to_string(type) + "\t9\n";
    const auto result = store.append({binding(endpoint), "audit", row, JournalMode::Audit, 1795000000000ULL + n});
    require(result.status == StoreStatus::Ok, "audit admission");
    if (index) { require(store.index(result.id).status == StoreStatus::Ok, "audit indexing"); }
    return result.id;
}
SystemDetectionReport scan(const EventStore& store, char endpoint = 'a') {
    return detect_system_integrity(store, binding(endpoint), EvidenceTrust::VerifiedStored, Coverage::Partial);
}
void positive() {
    MemoryEventStore store;
    const auto service = append(store, 1, 1130);
    const auto caps = append(store, 2, 1321);
    const auto config = append(store, 3, 1305);
    const auto anomaly = append(store, 4, 1702);
    const auto integrity = append(store, 5, 1800);
    const auto unknown = append(store, 6, 65535);
    append(store, 7, 1131, 'e');
    const auto row = "auth\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' + std::string(32, 'd') + "\tssh.service\tssh-failed\n";
    const auto auth = store.append({binding(), "ssh.service", row, JournalMode::Authentication, 1795000000008ULL});
    require(auth.status == StoreStatus::Ok && store.index(auth.id).status == StoreStatus::Ok, "auth fixture");
    const auto before = store.search({});
    require(before.events.size() == 8 && before.events.front().audit_type == 1130 && before.events.back().audit_type == 0, "projection");
    const auto report = scan(store);
    require(report.status == D::Evaluated && report.observed == 6 && report.unmatched == 1 && report.findings.size() == 5, "scope and count");
    const auto& findings = report.findings;
    require(findings[0].evidence_id == service && findings[0].rule_id == "audit-service-start" && findings[0].severity == RuleSeverity::Informational, "service evidence");
    require(findings[1].evidence_id == caps && findings[1].rule_id == "audit-file-capabilities", "privilege evidence");
    require(findings[2].evidence_id == config && findings[2].rule_id == "audit-config-change", "configuration evidence");
    require(findings[3].evidence_id == anomaly && findings[3].severity == RuleSeverity::High && findings[3].rule_id == "audit-anomalous-link", "anomaly evidence");
    require(findings[4].evidence_id == integrity && findings[4].audit_type == 1800 && findings[4].severity == RuleSeverity::Medium, "integrity observation");
    for (const auto& finding : findings) { require(finding.rule_version == 1 && finding.coverage == Coverage::Partial && finding.evidence_id != unknown, "finding metadata"); }
    require(scan(store) == report && scan(store, 'e').findings.size() == 1, "determinism or endpoint isolation");
    const auto after = store.search({});
    require(after.revision == before.revision && after.events.size() == before.events.size(), "store mutation");
    require(detect_system_integrity(store, "", EvidenceTrust::VerifiedStored, Coverage::Partial).status == D::Invalid, "empty binding");
    require(detect_system_integrity(store, binding(), EvidenceTrust::Unverified, Coverage::Partial).status == D::Unverified, "unverified");
    append(store, 9, 1305, 'e', false);
    const auto pending = scan(store);
    require(pending.status == D::Unavailable && pending.findings.empty() && pending.observed == 0, "partial result on pending index");
}
void capacity() {
    MemoryEventStore store;
    const auto empty = scan(store);
    require(empty.status == D::Evaluated && empty.findings.empty() && empty.observed == 0, "empty snapshot");
    unsigned n = 0;
    for (const auto& rule : system_rules()) {
        ++n;
        append(store, n, static_cast<unsigned>(rule.audit_type));
    }
    const auto catalog = scan(store);
    require(catalog.findings.size() == system_rules().size(), "catalog coverage");
    for (std::size_t i = 0; i < system_rules().size(); ++i) {
        const auto& rule = system_rules()[i];
        const auto& finding = catalog.findings[i];
        require(finding.rule_id == rule.id && finding.rule_version == rule.version && finding.audit_type == rule.audit_type && finding.severity == rule.severity, "catalog metadata");
    }
    for (++n; n <= 128; ++n) { append(store, n, 1131); }
    const auto result = scan(store);
    require(result.status == D::Evaluated && result.observed == 128 && result.findings.size() == 128 && result.findings.back().evidence_id == 128, "bounded pagination");
}
// Fault-injecting trusted-contract adapter. No real credentials or backend mutation.
class FaultStore final : public EventStore {
public:
    enum class Fault { None, WrongMode, MissingType, DuplicateId, Stale, Oversize, WrongSource, EmptyMore, PendingError };
    explicit FaultStore(Fault fault) : EventStore({}), fault_(fault) {
        for (unsigned i = 1; i <= 33; ++i) { append_fixture(i); }
    }
    mutable unsigned calls{};
    ReadResult<StorageUsage> usage() const override { return store_.usage(); }
    Durability durability() const noexcept override { return Durability::Volatile; }
    AppendResult append(const RawInput&) override { return {}; }
    IndexResult index(EventId) override { return {}; }
    ReadResult<RawEvidence> raw(EventId) const override { throw std::runtime_error("unexpected raw read"); }
    ReadResult<knetsentry::agent::NormalizedEvent> normalized(EventId) const override { throw std::runtime_error("unexpected normalized read"); }
    SearchPage search(const SearchQuery& query) const override {
        ++calls;
        auto page = store_.search(query);
        if (query.after == 0 || page.events.empty()) { return page; }
        switch (fault_) {
        case Fault::None: case Fault::PendingError: break;
        case Fault::WrongMode: page.events.front().source_mode = JournalMode::Authentication; break;
        case Fault::MissingType: page.events.front().audit_type = 0; break;
        case Fault::DuplicateId: page.events.front().id = query.after; break;
        case Fault::Stale: ++page.revision; break;
        case Fault::Oversize: page.events.resize(33); break;
        case Fault::WrongSource: page.events.front().source_unit = "ssh.service"; break;
        case Fault::EmptyMore: page.events.clear(); page.more = true; break;
        }
        return page;
    }
    PendingPage pending(EventId after, std::optional<std::uint64_t> rev, std::size_t limit) const override {
        if (fault_ == Fault::PendingError) { return {}; }
        return store_.pending(after, rev, limit);
    }
    StoreStatus set_hold(EventId, bool) override { return StoreStatus::Invalid; }
    RetentionPreview preview_retention(std::uint64_t, std::size_t) const override { return {}; }
    RetentionResult apply_retention(const RetentionPlan&) override { return {}; }
private:
    void append_fixture(unsigned n) { ::append(store_, n, 1305); }
    Fault fault_;
    MemoryEventStore store_;
};
void negative() {
    using F = FaultStore::Fault;
    FaultStore normal(F::None);
    require(detect_system_integrity(normal, binding(), EvidenceTrust::Unverified, Coverage::Partial).status == D::Unverified && normal.calls == 0, "unverified accessed store");
    require(scan(normal).findings.size() == 33, "valid backend");
    for (const auto fault : {F::WrongMode, F::MissingType, F::DuplicateId, F::Stale, F::Oversize, F::WrongSource, F::EmptyMore, F::PendingError}) {
        FaultStore store(fault);
        const auto report = scan(store);
        require((report.status == D::Invalid || report.status == D::Unavailable) && report.findings.empty() && report.observed == 0, "fault leaked partial findings");
    }
}
} // namespace
int main() {
    try { positive(); capacity(); negative(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    std::cout << "M7.4 Audit rule catalog, minimized projection, evidence linkage and scope: PASS\n";
    std::cout << "M7.4 bounded pagination, trust refusal, malformed pages and pending index: PASS\n";
    return 0;
}

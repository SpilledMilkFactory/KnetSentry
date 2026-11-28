// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/alerts.hpp>
#include <knetsentry/detection/authentication_patterns.hpp>
#include <knetsentry/detection/system_integrity.hpp>
#include <knetsentry/storage/sqlite_event_store.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>

namespace {
using namespace knetsentry::detection;
using namespace knetsentry::storage;
using namespace knetsentry::agent;
constexpr auto trust = EvidenceTrust::VerifiedStored;
constexpr auto coverage = Coverage::Partial;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
class Fixture final {
public:
    Fixture() {
        char pattern[] = "/var/tmp/ks-m78-XXXXXX";
        const auto* result = ::mkdtemp(pattern);
        require(result != nullptr, "private fixture"); path = result;
    }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(path, error); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    std::string path;
};
std::string binding(char endpoint = 'a') { return std::string(32, endpoint) + std::string(64, 'b'); }
std::string row(unsigned n, std::string_view source, std::string_view category) {
    return "cursor" + std::to_string(n) + "\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + '\t' + std::string(source) + '\t' + std::string(category) + '\n';
}
EventId append(EventStore& store, unsigned n, std::uint64_t time, std::string_view category,
    char endpoint = 'a', std::string_view source = "ssh.service", JournalMode mode = JournalMode::Authentication) {
    const auto key = binding(endpoint); const auto data = row(n, source, category);
    const auto result = store.append({key, source, data, mode, time});
    require(result.status == StoreStatus::Ok && store.index(result.id).status == StoreStatus::Ok, "admission/index");
    return result.id;
}
void authentication_matrix(EventStore& store) {
    append(store, 1, 1000, "ssh-failed");
    append(store, 2, 1001, "ssh-failed", 'e');
    append(store, 3, 1002, "ssh-failed", 'a', "sshd.service");
    append(store, 4, 1100, "ssh-failed");
    append(store, 5, 1101, "ssh-accepted");
    append(store, 6, 1200, "ssh-failed");
    append(store, 7, 1201, "redacted");
    append(store, 8, 1202, "ssh-failed");
    append(store, 9, 1203, "ssh-accepted");
    append(store, 10, 1300, "ssh-invalid-user");
    append(store, 11, 1301, "authentication-failed");
    const auto key = binding(); const auto duplicate = row(4, "ssh.service", "ssh-failed");
    const auto changed = row(4, "ssh.service", "ssh-accepted");
    const auto before = store.search({});
    const auto retry = store.append({key, "ssh.service", duplicate, JournalMode::Authentication, 2000});
    require(retry.status == StoreStatus::ExactRetry && retry.id == 4, "exact retry");
    require(store.append({key, "ssh.service", changed, JournalMode::Authentication, 2000}).status == StoreStatus::Conflict, "conflicting duplicate");
    require(store.append({key, "ssh.service", "malformed\n", JournalMode::Authentication, 2000}).status == StoreStatus::Invalid, "malformed admission");
    const auto after = store.search({});
    require(after.revision == before.revision && after.events.size() == 11, "rejected input changed store");
    using P = AuthenticationPattern;
    for (const std::uint64_t window : {99ULL, 100ULL, 101ULL}) {
        const auto report = detect_authentication(store, key, "ssh.service", trust, coverage, {2, window});
        require(report.status == PatternStatus::Evaluated && report.observed == 9 && report.coverage == coverage, "auth scope");
        std::vector<AuthenticationFinding> expected;
        if (window >= 100) { expected.push_back({P::RepeatedFailures, 1, RuleSeverity::Medium, coverage, {1, 4}}); }
        if (window >= 101) { expected.push_back({P::SuccessAfterFailures, 1, RuleSeverity::High, coverage, {1, 4, 5}}); }
        expected.push_back({P::InvalidUserObservation, 1, RuleSeverity::Low, coverage, {10}});
        expected.push_back({P::UnspecifiedActivityFailure, 1, RuleSeverity::Low, coverage, {11}});
        require(report.findings == expected, "auth golden timing/benign controls");
        require(detect_authentication(store, key, "ssh.service", trust, coverage, {2, window}) == report, "auth replay");
    }
    const auto denied = detect_authentication(store, key, "ssh.service", EvidenceTrust::Unverified, coverage);
    require(denied.status == PatternStatus::Unverified && denied.findings.empty(), "untrusted evidence");
}
void audit_matrix(EventStore& store) {
    // Keep the pointer-aligned member first to avoid unnecessary fixture padding.
    struct Expected { std::string_view id; unsigned type; RuleSeverity severity; };
    using S = RuleSeverity;
    constexpr Expected expected[] = {
        {"audit-service-start", 1130, S::Informational}, {"audit-service-stop", 1131, S::Informational},
        {"audit-daemon-config", 1203, S::Medium}, {"audit-config-change", 1305, S::Medium},
        {"audit-file-capabilities", 1321, S::Medium}, {"audit-capset", 1322, S::Medium},
        {"audit-netfilter-config", 1325, S::Medium}, {"audit-kernel-module", 1330, S::Medium},
        {"audit-mac-policy-load", 1403, S::Medium}, {"audit-mac-status", 1404, S::Medium},
        {"audit-anomalous-link", 1702, S::High}, {"audit-anomalous-create", 1703, S::High},
        {"audit-integrity-data", 1800, S::Medium}, {"audit-integrity-metadata", 1801, S::Medium},
        {"audit-integrity-status", 1802, S::Medium}, {"audit-integrity-pcr", 1804, S::Medium},
        {"audit-integrity-policy", 1805, S::Medium}, {"audit-ima-policy", 1807, S::Medium}};
    require(system_rules().size() == std::size(expected), "catalog changed");
    unsigned n = 20; std::vector<SystemFinding> golden;
    for (const auto& entry : expected) {
        ++n; const auto category = std::to_string(entry.type) + "\t9";
        const auto id = append(store, n, 2000 + n, category, 'a', "audit", JournalMode::Audit);
        golden.push_back({std::string(entry.id), 1, entry.severity, coverage, id, entry.type});
    }
    for (const auto type : {1129U, 1132U, 1803U, 1806U, 65535U}) {
        ++n; const auto category = std::to_string(type) + "\t9";
        append(store, n, 2000 + n, category, 'a', "audit", JournalMode::Audit);
    }
    append(store, 50, 2050, "1702\t9", 'e', "audit", JournalMode::Audit);
    const auto key = binding(); const auto report = detect_system_integrity(store, key, trust, coverage);
    require(report.status == SystemDetectionStatus::Evaluated && report.observed == 23 && report.unmatched == 5 && report.findings == golden, "Audit golden catalog/negative types");
    require(detect_system_integrity(store, key, trust, coverage) == report, "Audit replay");
}
SchedulePolicy policy() {
    SchedulePolicy p;
    p.store_identity = std::string(64, 'e'); p.binding = binding();
    p.threshold = 2; p.interval_ms = 10; p.window_ms = 100; p.suppression_ms = 20;
    p.rule.schema_version = ValidatedRuleSet::schema_version;
    p.rule.ocsf_version = NormalizedEvent::schema_version; p.rule.mapping_revision = NormalizedEvent::mapping_revision;
    p.rule.predicate = {"ssh-failure", 1, OcsfActivity::Logon, OcsfStatus::Failure, "ssh.service"};
    p.rule.title = "Authentication failures"; p.rule.description = "Synthetic fixture.";
    p.rule.severity = RuleSeverity::Medium; p.rule.source_mode = JournalMode::Authentication;
    return p;
}
std::string contents(const std::string& path) {
    std::ifstream input(path, std::ios::binary); require(input.is_open(), "fixture read");
    std::string data;
    char byte{};
    while (input.get(byte)) {
        require(data.size() < 16U * 1024U * 1024U, "fixture file limit");
        data.push_back(byte);
    }
    require(input.eof() && !input.bad(), "fixture read failure");
    return data;
}
void persistent_pipeline() {
    Fixture database; Fixture schedule; Fixture alerts; const auto p = policy();
    require(initialize_schedule(p, schedule.path) && initialize_alerts(p, alerts.path, true), "initialize pipeline");
    const auto tick = [&](const EventStore& store, std::uint64_t time, bool enabled = true) {
        return run_schedule(p, schedule.path, store, time, enabled, trust, coverage);
    };
    const auto publish = [&](const EventStore& store, std::uint64_t generation, std::uint64_t time) {
        return consume_alerts(p, alerts.path, schedule.path, store, generation, time, true, trust);
    };
    const auto ledger = alerts.path + "/alerts-m76.v1"; const auto state = schedule.path + "/schedule-m75.v1";
    {
        SqliteEventStore store(database.path);
        append(store, 1, 1000, "ssh-failed"); append(store, 2, 1001, "ssh-accepted"); append(store, 3, 1010, "ssh-failed");
        const auto saved = contents(state);
        require(tick(store, 1010, false).status == ScheduleStatus::Disabled && contents(state) == saved, "disabled mutation");
        const auto report = tick(store, 1010); const std::vector<EventId> expected{1, 3};
        require(report.status == ScheduleStatus::Evaluated && report.generation == 1 && report.findings.size() == 1 && report.findings.front().evidence_ids == expected, "first generation");
        require(publish(store, 1, 1010) == AlertResult::Ok, "first publish");
    }
    const auto first_ledger = contents(ledger); const auto evidence_db = contents(database.path + "/events-m64.sqlite3");
    {
        SqliteEventStore store(database.path, LegacyIntegrityPolicy::Reject, {}, StorageOpenMode::ExistingV4);
        const auto replay = tick(store, 1011);
        require(replay.status == ScheduleStatus::Replay && replay.generation == 1 && replay.findings.size() == 1, "restart replay");
        require(publish(store, 1, 1011) == AlertResult::ExactRetry && contents(ledger) == first_ledger, "lost ACK idempotence");
        require(acknowledge_schedule(p, schedule.path, 1), "commit ACK");
        require(tick(store, 1019).status == ScheduleStatus::NotDue, "interval minus one");
        require(update_alert(p, alerts.path, 1, 3, 1, AlertAction::Acknowledge, "analyst-1", "", 1019, true) == AlertResult::Ok, "ack lifecycle");
        require(update_alert(p, alerts.path, 1, 3, 1, AlertAction::AddNote, "analyst-1", "stale", 1020, true) == AlertResult::Conflict, "stale update");
    }
    require(contents(database.path + "/events-m64.sqlite3") == evidence_db, "lifecycle changed evidence bytes");
    {
        SqliteEventStore store(database.path, LegacyIntegrityPolicy::Reject, {}, StorageOpenMode::ExistingV4);
        append(store, 4, 1029, "ssh-failed"); append(store, 5, 1030, "ssh-failed");
        const auto report = tick(store, 1030); const std::vector<EventId> expected{4, 5};
        require(report.status == ScheduleStatus::Evaluated && report.generation == 2 && report.suppressed == 1 && report.findings.size() == 1 && report.findings.front().evidence_ids == expected, "suppression boundary");
        require(publish(store, 2, 1030) == AlertResult::Ok && acknowledge_schedule(p, schedule.path, 2), "second generation");
        const auto snapshot = read_alerts(p, alerts.path, true, false);
        require(snapshot.result == AlertResult::Ok && snapshot.alerts.size() == 2 && snapshot.alerts[0].status == AlertStatus::Acknowledged && snapshot.alerts[0].revision == 2 && snapshot.alerts[1].status == AlertStatus::Open, "restart lifecycle isolation");
        const auto original = store.raw(5);
        require(original.value && original.value->integrity && !snapshot.alerts[1].evidence.empty() && snapshot.alerts[1].evidence.back().sha256 == original.value->integrity->sha256, "digest linkage");
        const auto empty = tick(store, 1040);
        require(empty.status == ScheduleStatus::Evaluated && empty.observed == 0 && empty.findings.empty(), "checkpoint duplicate");
        const auto saved_state = contents(state); const auto saved_ledger = contents(ledger);
        append(store, 6, 1060, "ssh-failed");
        require(tick(store, 1050).status == ScheduleStatus::Unavailable && contents(state) == saved_state && contents(ledger) == saved_ledger, "future event atomic refusal");
        const auto recovery = tick(store, 1060);
        require(recovery.status == ScheduleStatus::Evaluated && recovery.findings.size() == 1, "clock recovery");
    }
}
} // namespace
int main() {
    ::umask(0077);
    try {
        MemoryEventStore memory; authentication_matrix(memory); audit_matrix(memory);
        Fixture database; SqliteEventStore sqlite(database.path); authentication_matrix(sqlite); audit_matrix(sqlite);
        std::cout << "M7.8 independent authentication and Audit golden fixtures on memory and SQLite: PASS\n";
        persistent_pipeline();
        std::cout << "M7.8 composed scheduling, replay, suppression, alert lifecycle and evidence invariance: PASS\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}

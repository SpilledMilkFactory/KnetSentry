// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/alerts.hpp>
#include <knetsentry/storage/sqlite_event_store.hpp>
#include <filesystem>
#include <fstream>
#include <sys/resource.h>
#include <csignal>
#include <fcntl.h>
#include <sys/file.h>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using namespace knetsentry::detection;
using namespace knetsentry::storage;
using namespace knetsentry::agent;
using R = AlertResult;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
class Fixture final {
public:
    Fixture() {
        char pattern[] = "/var/tmp/ks-m76-XXXXXX";
        const auto* p = ::mkdtemp(pattern); require(p != nullptr, "fixture directory"); path = p;
    }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(path, error); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    std::string path;
};
SchedulePolicy policy() {
    SchedulePolicy p;
    p.store_identity = std::string(64, 'e'); p.binding = std::string(32, 'a') + std::string(64, 'b');
    p.threshold = 2; p.interval_ms = 1; p.suppression_ms = 0;
    p.rule.schema_version = ValidatedRuleSet::schema_version;
    p.rule.ocsf_version = NormalizedEvent::schema_version; p.rule.mapping_revision = NormalizedEvent::mapping_revision;
    p.rule.predicate = {"ssh-failure", 1, OcsfActivity::Logon, OcsfStatus::Failure, "ssh.service"};
    p.rule.title = "Authentication failures"; p.rule.description = "Synthetic fixture.";
    p.rule.severity = RuleSeverity::Medium; p.rule.source_mode = JournalMode::Authentication;
    return p;
}
EventId append(EventStore& store, const SchedulePolicy& p, unsigned n, std::uint64_t time) {
    const auto row = "cursor" + std::to_string(n) + "\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + "\tssh.service\tssh-failed\n";
    const auto result = store.append({p.binding, "ssh.service", row, JournalMode::Authentication, time});
    require(result.status == StoreStatus::Ok && store.index(result.id).status == StoreStatus::Ok, "admission");
    return result.id;
}
void batch() {
    auto p = policy(); p.threshold = 1;
    Fixture alerts; Fixture scheduler; Fixture db;
    require(initialize_alerts(p, alerts.path, true) && initialize_schedule(p, scheduler.path), "batch initialization");
    SqliteEventStore store(db.path);
    const auto first = append(store, p, 1, 1000);
    const auto second = append(store, p, 2, 1001);
    const auto report = run_schedule(p, scheduler.path, store, 1001, true, EvidenceTrust::VerifiedStored, Coverage::Partial);
    require(report.status == ScheduleStatus::Evaluated && report.findings.size() == 2, "batch candidates");
    require(consume_alerts(p, alerts.path, scheduler.path, store, 1, 1002, true, EvidenceTrust::Unverified) == R::Unverified, "trust refusal");
    require(consume_alerts(p, alerts.path, scheduler.path, store, 1, 1002, true, EvidenceTrust::VerifiedStored) == R::Ok, "batch publication");
    require(read_alerts(p, alerts.path, true).alerts.size() == 2 && acknowledge_schedule(p, scheduler.path, 1), "batch acknowledgement");
    const auto third = append(store, p, 3, 1003);
    const auto fourth = append(store, p, 4, 1004);
    const auto next = run_schedule(p, scheduler.path, store, 1004, true, EvidenceTrust::VerifiedStored, Coverage::Partial);
    require(next.status == ScheduleStatus::Evaluated && next.findings.size() == 2 && next.generation == 2, "second batch");
    for (const auto id : {first, second, third}) { require(store.set_hold(id, true) == StoreStatus::Ok, "retention fixture hold"); }
    const auto plan = store.preview_retention(1005, 32);
    require(plan.plan && store.apply_retention(*plan.plan).status == StoreStatus::Ok && store.raw(fourth).status == StoreStatus::NotFound, "remove later candidate evidence");
    require(consume_alerts(p, alerts.path, scheduler.path, store, 2, 1005, true, EvidenceTrust::VerifiedStored) == R::Unavailable, "later evidence refusal");
    require(read_alerts(p, alerts.path, true).alerts.size() == 2 && pending_schedule(p, scheduler.path, EvidenceTrust::VerifiedStored).generation == 2, "no partial batch or ACK");
    std::cout << "M7.6 atomic generation and later evidence refusal: PASS\n";
}
void verify() {
    const auto p = policy(); Fixture alerts; Fixture scheduler; Fixture db;
    require(!initialize_alerts(p, alerts.path, false), "authorization");
    require(read_alerts(p, alerts.path, true).result == R::Unavailable, "missing ledger");
    require(initialize_alerts(p, alerts.path, true) && !initialize_alerts(p, alerts.path, true), "explicit initialization");
    require(initialize_schedule(p, scheduler.path), "schedule initialization");
    EventId first{}, trigger{};
    {
        SqliteEventStore store(db.path);
        first = append(store, p, 1, 1000); trigger = append(store, p, 2, 1001);
        const auto report = run_schedule(p, scheduler.path, store, 1001, true, EvidenceTrust::VerifiedStored, Coverage::Partial);
        require(report.status == ScheduleStatus::Evaluated && report.findings.size() == 1 && report.generation == 1, "candidate");
    }
    const auto child = ::fork(); require(child >= 0, "fork");
    if (child == 0) {
        try {
            SqliteEventStore store(db.path, LegacyIntegrityPolicy::Reject, {}, StorageOpenMode::ExistingV4);
            ::_exit(consume_alerts(p, alerts.path, scheduler.path, store, 1, 1002, true, EvidenceTrust::VerifiedStored) == R::Ok ? 0 : 1);
        } catch (...) { ::_exit(2); }
    }
    int status{}; require(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child publish");
    SqliteEventStore store(db.path, LegacyIntegrityPolicy::Reject, {}, StorageOpenMode::ExistingV4);
    const auto raw_before = store.raw(first); require(raw_before.value.has_value(), "original evidence");
    const auto consume = [&](std::uint64_t gen, std::uint64_t now) {
        return consume_alerts(p, alerts.path, scheduler.path, store, gen, now, true, EvidenceTrust::VerifiedStored);
    };
    const auto update = [&](std::uint64_t rev, AlertAction action, std::string_view note, std::uint64_t now) {
        return update_alert(p, alerts.path, 1, trigger, rev, action, "analyst-1", note, now, true);
    };
    require(consume(2, 1003) == R::Conflict && consume(1, 1003) == R::ExactRetry, "durable replay");

    auto snapshot = read_alerts(p, alerts.path, true);
    require(snapshot.result == R::Ok && snapshot.alerts.size() == 1 && snapshot.alerts.front().evidence.size() == 2 &&
        snapshot.alerts.front().evidence.front().id == first && snapshot.source == "ssh.service" && snapshot.severity == RuleSeverity::Medium, "persisted identity");
    require(read_alerts(p, alerts.path, false).result == R::Unverified, "read authorization");
    require(update_alert(p, alerts.path, 1, trigger, 1, AlertAction::Acknowledge, "analyst", "", 1004, false) == R::Unverified, "write authorization");
    require(update(1, AlertAction::Resolve, "", 1004) == R::Conflict, "invalid transition");
    require(update(1, AlertAction::AddNote, "line\nbreak", 1004) == R::Invalid, "control character");
    const auto writer = ::fork(); require(writer >= 0, "fork write failure");
    if (writer == 0) {
        try {
            const struct rlimit limit{1, 1};
            if (::signal(SIGXFSZ, SIG_IGN) == SIG_ERR || ::setrlimit(RLIMIT_FSIZE, &limit) != 0) { ::_exit(2); }
            ::_exit(update(1, AlertAction::Acknowledge, "", 1004) == R::Unavailable ? 0 : 1);
        } catch (...) { ::_exit(3); }
    }
    require(::waitpid(writer, &status, 0) == writer && WIFEXITED(status) && WEXITSTATUS(status) == 0, "actual write failure");
    require(read_alerts(p, alerts.path, true).alerts.front().revision == 1, "failed update preserved state");
    require(update(1, AlertAction::Acknowledge, "", 1004) == R::Ok, "acknowledge after recovery");
    require(update(1, AlertAction::AddNote, "stale", 1005) == R::Conflict, "stale revision");
    require(update(2, AlertAction::AddNote, "clock", 1003) == R::Conflict, "clock regression");
    require(update(2, AlertAction::AddNote, "Synthetic review", 1005) == R::Ok, "note");
    require(update(3, AlertAction::Resolve, "", 1006) == R::Ok, "resolve");
    require(consume(1, 1006) == R::ExactRetry, "replay after lifecycle update");
    require(acknowledge_schedule(p, scheduler.path, 1) && consume(1, 1006) == R::Unavailable, "explicit ACK");
    snapshot = read_alerts(p, alerts.path, true);
    require(snapshot.result == R::Ok && snapshot.alerts.size() == 1, "reopen");
    const auto& a = snapshot.alerts.front();
    require(a.status == AlertStatus::Resolved && a.revision == 4 && a.created_ms == 1002 && a.acknowledged_ms == 1004 &&
        a.resolved_ms == 1006 && a.notes.size() == 1 && a.notes.front().text == "Synthetic review", "lifecycle persisted");
    const auto raw_after = store.raw(first);
    require(raw_after.value && raw_before.value->canonical_row == raw_after.value->canonical_row &&
        raw_before.value->integrity && raw_after.value->integrity && raw_before.value->integrity->sha256 == raw_after.value->integrity->sha256 &&
        raw_before.value->held == raw_after.value->held, "original unchanged");
    for (std::uint64_t rev = 4; rev < 11; ++rev) { require(update(rev, AlertAction::AddNote, "Review", 1007) == R::Ok, "bounded notes"); }
    require(update(11, AlertAction::AddNote, "Overflow", 1008) == R::Capacity, "note limit");
    auto other = p; other.store_identity = std::string(64, 'f');
    require(read_alerts(other, alerts.path, true).result == R::Unavailable, "policy binding");
    const auto path = alerts.path + "/alerts-m76.v1";
    require(::chmod(path.c_str(), 0644) == 0 && read_alerts(p, alerts.path, true).result == R::Unavailable && ::chmod(path.c_str(), 0600) == 0, "unsafe mode");
    const auto temporary = alerts.path + "/alerts-m76.pending";
    require(::symlink(path.c_str(), temporary.c_str()) == 0 && read_alerts(p, alerts.path, true).result == R::Unavailable && ::unlink(temporary.c_str()) == 0, "unsafe pending");
    const auto linked = alerts.path + "/linked";
    require(::link(path.c_str(), linked.c_str()) == 0 && read_alerts(p, alerts.path, true).result == R::Unavailable && ::unlink(linked.c_str()) == 0, "hard link refusal");
    const int lock = ::open(alerts.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(lock >= 0 && ::flock(lock, LOCK_EX | LOCK_NB) == 0, "test lock");
    require(read_alerts(p, alerts.path, true).result == R::Unavailable, "lock refusal");
    require(::close(lock) == 0, "unlock");
    const auto next = append(store, p, 3, 1010);
    const auto report = run_schedule(p, scheduler.path, store, 1010, true, EvidenceTrust::VerifiedStored, Coverage::Partial);
    require(report.status == ScheduleStatus::Evaluated && report.generation == 2 && report.findings.size() == 1, "next generation");
    const auto retention = store.preview_retention(1011, 32);
    require(retention.plan && store.apply_retention(*retention.plan).status == StoreStatus::Ok, "retention fixture");
    require(store.raw(next).status == StoreStatus::NotFound && consume(2, 1012) == R::Unavailable, "missing evidence refusal");
    require(read_alerts(p, alerts.path, true).alerts.size() == 1, "historical references retained");
    {
        std::ofstream corrupt(path, std::ios::app | std::ios::binary);
        corrupt << "x";
        corrupt.close(); require(corrupt.good(), "corrupt fixture");
    }
    require(read_alerts(p, alerts.path, true).result == R::Unavailable, "checksum refusal");
    std::cout << "M7.6 durable alerts, replay, lifecycle, notes and original evidence: PASS\n"
              << "M7.6 authorization, stale revisions, private state, write recovery and missing evidence: PASS\n";
}
} // namespace
int main() {
    try { verify(); batch(); return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

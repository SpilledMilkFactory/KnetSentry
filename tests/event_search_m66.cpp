// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/storage/sqlite_event_store.hpp>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <utility>

namespace {
using namespace knetsentry::storage;
using namespace knetsentry::agent;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
class Fixture final {
public:
    Fixture() { char name[] = "/var/tmp/ks-m66-XXXXXX"; const auto* p = mkdtemp(name); require(p != nullptr, "fixture"); path = p; }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(path, error); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    std::string path;
    std::string db() const { return path + "/events-m64.sqlite3"; }
};
class External final {
public:
    explicit External(const std::string& path) {
        if (sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
            sqlite3_close(db_); throw std::runtime_error("fixture DB");
        }
    }
    ~External() { sqlite3_close(db_); }
    External(const External&) = delete;
    External& operator=(const External&) = delete;
    void sql(const char* command) { require(sqlite3_exec(db_, command, nullptr, nullptr, nullptr) == SQLITE_OK, "fixture SQL"); }
    bool plan_contains(const char* query, std::string_view index) {
        sqlite3_stmt* stmt{};
        const auto rc = sqlite3_prepare_v2(db_, query, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) { sqlite3_finalize(stmt); throw std::runtime_error("query plan"); }
        bool found = false;
        int step{};
        while ((step = sqlite3_step(stmt)) == SQLITE_ROW) {
            const auto* detail = sqlite3_column_text(stmt, 3);
            if (detail && std::string_view(reinterpret_cast<const char*>(detail)).find(index) != std::string_view::npos) { found = true; }
        }
        sqlite3_finalize(stmt); require(step == SQLITE_DONE, "plan completion"); return found;
    }
    int version() {
        sqlite3_stmt* stmt{};
        const auto rc = sqlite3_prepare_v2(db_, "PRAGMA user_version", -1, &stmt, nullptr);
        if (rc != SQLITE_OK) { sqlite3_finalize(stmt); throw std::runtime_error("version query"); }
        const int value = sqlite3_step(stmt) == SQLITE_ROW ? sqlite3_column_int(stmt, 0) : -1;
        sqlite3_finalize(stmt); return value;
    }
private:
    sqlite3* db_{};
};
std::string binding(char endpoint) { return std::string(32, endpoint) + std::string(64, 'b'); }
constexpr std::uint64_t base_time = 1795000000123;
void populate(EventStore& store) {
    const auto a = binding('a'); const auto b = binding('e');
    const auto add = [&](EventId id, std::string_view source, JournalMode mode, std::string_view suffix,
                         std::uint64_t offset, std::string_view target, bool indexed = true) {
        const auto wire = "cursor-" + std::to_string(id) + '\t' + std::to_string((base_time + offset) * 1000U) + "\t42\t" +
            std::string(32, 'c') + '\t' + std::string(32, 'd') + '\t' + std::string(source) + std::string(suffix) + '\n';
        const auto result = store.append({target, source, wire, mode, 100 + id});
        require(result.status == StoreStatus::Ok && result.id == id, "fixture admission");
        if (indexed) { require(store.index(id).status == StoreStatus::Ok, "fixture indexing"); }
    };
    add(1, "ssh.service", JournalMode::Authentication, "\tssh-accepted", 2, a);
    add(2, "ssh.service", JournalMode::Authentication, "\tssh-failed", 0, a);
    add(3, "sshd.service", JournalMode::Authentication, "\tssh-failed", 1, b);
    add(4, "ssh.service", JournalMode::Authentication, "\tredacted", 1, a);
    add(5, "ssh.service", JournalMode::Metadata, "", 1, b);
    add(6, "audit", JournalMode::Audit, "\t1100\t9", 2, b);
    add(7, "systemd-logind.service", JournalMode::Authentication, "\tlogin-session-removed", 0, b);
    add(8, "ssh.service", JournalMode::Authentication, "\tssh-failed", 0, a, false);
}
void expect(EventStore& store, const SearchQuery& q, const std::vector<EventId>& ids) {
    const auto page = store.search(q);
    require(page.status == StoreStatus::Ok && !page.more && page.events.size() == ids.size(), "query count/status");
    for (std::size_t i = 0; i < ids.size(); ++i) {
        require(page.events[i].id == ids[i] && page.events[i].severity == OcsfSeverity::Unknown, "known IDs/severity");
    }
}
void verify_queries(EventStore& store) {
    const auto a = binding('a'); const auto b = binding('e');
    expect(store, {}, {1,2,3,4,5,6,7});
    SearchQuery q; q.from_ms = base_time; q.through_ms = base_time; expect(store, q, {2,7});
    q.through_ms = base_time + 1; expect(store, q, {2,3,4,5,7});
    q = {}; q.source_unit = "ssh.service"; expect(store, q, {1,2,4,5});
    q.source_mode = JournalMode::Authentication; expect(store, q, {1,2,4});
    q.binding = a; q.category = OcsfCategory::IdentityAndAccessManagement; q.status_id = OcsfStatus::Failure;
    q.activity = OcsfActivity::Logon; q.mapping = MappingResult::Classified; q.severity = OcsfSeverity::Unknown;
    q.from_ms = base_time; q.through_ms = base_time; expect(store, q, {2});
    q.binding = b; expect(store, q, {});
    q = {}; q.source_mode = JournalMode::Audit; expect(store, q, {6});
    q.source_unit = "audit"; expect(store, q, {6});
    q = {}; q.category = OcsfCategory::Unknown; expect(store, q, {4,5,6});
    q.class_uid = OcsfClass::Authentication; expect(store, q, {});
    q = {}; q.mapping = MappingResult::Redacted; expect(store, q, {4});
    q = {}; q.activity = OcsfActivity::Logoff; expect(store, q, {7});
    q = {}; q.severity = OcsfSeverity::Unknown; expect(store, q, {1,2,3,4,5,6,7});
    for (const auto severity : {OcsfSeverity::Informational, OcsfSeverity::Low, OcsfSeverity::Medium,
             OcsfSeverity::High, OcsfSeverity::Critical, OcsfSeverity::Fatal, OcsfSeverity::Other}) {
        q.severity = severity; expect(store, q, {});
    }
    q = {}; q.from_ms = std::numeric_limits<std::uint64_t>::max(); expect(store, q, {});
    q = {}; q.status_id = OcsfStatus::Failure; q.limit = 1;
    const auto first = store.search(q); require(first.status == StoreStatus::Ok && first.more && first.events.size() == 1 && first.events[0].id == 2, "first filtered page");
    const auto& item = first.events[0];
    require(item.category == OcsfCategory::IdentityAndAccessManagement && item.source_mode == JournalMode::Authentication && item.source_unit == "ssh.service" && item.time_ms == base_time && item.received_ms == 102, "summary source and category");
    q.after = item.id; q.revision = first.revision;
    expect(store, q, {3});
    q.after = 3; expect(store, q, {});
    q.after = 2; q.revision.reset(); require(store.search(q).status == StoreStatus::Invalid, "unversioned continuation");
    q = {}; q.limit = 0; require(store.search(q).status == StoreStatus::Invalid, "zero limit");
    q.limit = 33; require(store.search(q).status == StoreStatus::Invalid, "large limit");
    q = {}; q.from_ms = 2; q.through_ms = 1; require(store.search(q).status == StoreStatus::Invalid, "reversed time");
    q = {}; q.binding = "invalid"; require(store.search(q).status == StoreStatus::Invalid, "invalid binding");
    q = {}; q.source_unit = "*.service"; require(store.search(q).status == StoreStatus::Invalid, "wildcard rejected");
    q.source_unit = "x' OR 1=1 --"; require(store.search(q).status == StoreStatus::Invalid, "SQL-like source rejected");
    const std::string oversized(129, 'x'); q.source_unit = oversized; require(store.search(q).status == StoreStatus::Invalid, "oversized unit");
    q = {}; q.source_mode = JournalMode::Unsupported; require(store.search(q).status == StoreStatus::Invalid, "unsupported mode");
    q = {}; q.limit = 1; const auto snapshot = store.search(q);
    require(store.index(8).status == StoreStatus::Ok, "publish pending");
    q.revision = snapshot.revision; q.after = 1; require(store.search(q).status == StoreStatus::Stale, "mutation invalidates continuation");
    q = {}; q.status_id = OcsfStatus::Failure; expect(store, q, {2,3,8});
}
void verify_page_bound(EventStore& store) {
    const auto target = binding('a');
    for (EventId i = 1; i <= 40; ++i) {
        const auto wire = "page-" + std::to_string(i) + "\t1795000000123456\t42\t" +
            std::string(32, 'c') + '\t' + std::string(32, 'd') + "\tssh.service\tssh-failed\n";
        const auto added = store.append({target, "ssh.service", wire, JournalMode::Authentication, 100});
        require(added.status == StoreStatus::Ok && added.id == i && store.index(i).status == StoreStatus::Ok, "page dataset");
    }
    SearchQuery q; q.source_unit = "ssh.service"; q.severity = OcsfSeverity::Unknown;
    const auto first = store.search(q);
    require(first.status == StoreStatus::Ok && first.more && first.events.size() == EventStore::max_page, "maximum page bound");
    for (std::size_t i = 0; i < first.events.size(); ++i) { require(first.events[i].id == i + 1, "first page ordering"); }
    q.after = first.events.back().id; q.revision = first.revision;
    expect(store, q, {33,34,35,36,37,38,39,40});
}
void verify() {
    MemoryEventStore memory; populate(memory); verify_queries(memory);
    MemoryEventStore larger; verify_page_bound(larger);
    Fixture pages; { SqliteEventStore store(pages.path); verify_page_bound(store); }
    Fixture f;
    std::string digest;
    { SqliteEventStore store(f.path); populate(store); verify_queries(store);
      const auto raw = store.raw(1); require(raw.value && raw.value->integrity, "original commitment"); digest = raw.value->integrity->sha256; }
    // Simulate exact v3 schema. Migration must verify, never rebaseline evidence.
    { External db(f.db()); require(db.version() == 4, "new schema"); db.sql("BEGIN; DROP INDEX event_mode; DROP INDEX event_source; DROP INDEX event_time; PRAGMA user_version=3; COMMIT"); }
    { SqliteEventStore store(f.path); const auto raw = store.raw(1);
      require(raw.value && raw.value->integrity && raw.value->integrity->sha256 == digest && raw.value->integrity->origin == IntegrityOrigin::Admission, "migration preserves digest");
      SearchQuery q; q.source_unit = "ssh.service"; q.status_id = OcsfStatus::Failure; expect(store, q, {2,8});
      { External db(f.db()); require(db.version() == 4, "migration schema");
        require(db.plan_contains("EXPLAIN QUERY PLAN SELECT id FROM events WHERE time_ms IS NOT NULL AND unit='ssh.service' AND mode=1 ORDER BY id", "event_source"), "source index selected");
        require(db.plan_contains("EXPLAIN QUERY PLAN SELECT id FROM events WHERE time_ms IS NOT NULL AND mode=1 ORDER BY id", "event_mode"), "mode index selected");
        require(db.plan_contains("EXPLAIN QUERY PLAN SELECT id FROM events WHERE time_ms IS NOT NULL AND time_ms BETWEEN 1795000000123 AND 1795000000124", "event_time"), "time index selected");
        db.sql("UPDATE events SET received=999 WHERE id=1"); }
      q = {}; q.severity = OcsfSeverity::High; const auto bad = store.search(q);
      require(bad.status == StoreStatus::IntegrityFailure && bad.events.empty() && !bad.more, "impossible severity still verifies integrity");
      q = {}; q.source_unit = "audit"; require(store.search(q).status == StoreStatus::IntegrityFailure, "excluded corruption detected"); }
    { External db(f.db()); db.sql("BEGIN; DROP INDEX event_mode; DROP INDEX event_source; DROP INDEX event_time; PRAGMA user_version=3; COMMIT"); }
    bool rejected = false;
    try { SqliteEventStore store(f.path); } catch (const std::runtime_error&) { rejected = true; }
    require(rejected, "corrupt v3 refused");
    { External db(f.db()); require(db.version() == 3, "failed migration leaves v3"); }
}
} // namespace
int main() {
    try { verify(); std::cout << "M6.6 bounded event search, typed filters, pagination, index migration and integrity: PASS\n"; return 0; }
    catch (const std::exception& e) { std::cerr << "M6.6: " << e.what() << '\n'; return 1; }
}

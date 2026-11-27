// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/storage/sqlite_event_store.hpp>
#include <knetsentry/agent/delivery.hpp>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <type_traits>

namespace {
using namespace knetsentry::storage;
using namespace knetsentry::agent;
static_assert(!std::is_base_of_v<ReceiptSink, SqliteEventStore>);
void require(bool ok, const char* msg) { if (!ok) { throw std::runtime_error(msg); } }
class Fixture final {
public:
    Fixture() {
        char name[] = "/var/tmp/ks-m64-XXXXXX";
        const auto* p = mkdtemp(name); require(p != nullptr, "fixture directory"); path = p;
    }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(path, error); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    std::string path;
    std::string db() const { return path + "/events-m64.sqlite3"; }
};
class External final {
public:
    explicit External(const std::string& path) {
        const auto rc = sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr);
        if (rc != SQLITE_OK) { sqlite3_close(db); throw std::runtime_error("fixture database"); }
    }
    ~External() { sqlite3_close(db); }
    External(const External&) = delete;
    External& operator=(const External&) = delete;
    void sql(const char* command) { require(sqlite3_exec(db, command, nullptr, nullptr, nullptr) == SQLITE_OK, "fixture SQL"); }
    sqlite3* db{};
};
bool rejects(const std::string& path) {
    try { SqliteEventStore store(path); } catch (const std::runtime_error&) { return true; }
    return false;
}
std::string row(std::string_view cursor, std::string_view suffix = "ssh-accepted") {
    return std::string(cursor) + "\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + "\tssh.service\t" + std::string(suffix) + '\n';
}
void verify() {
    Fixture f;
    const auto binding = std::string(32, 'a') + std::string(64, 'b');
    const auto original = row("first"); const auto redacted = row("pending", "redacted");
    EventId first{}, pending{}; std::uint64_t prior_revision{};
    {
        SqliteEventStore store(f.path);
        require(store.durability() == Durability::Durable && rejects(f.path), "durability and exclusive owner");
        const auto result = store.append({binding, "ssh.service", original, JournalMode::Authentication, 100});
        first = result.id; require(result.status == StoreStatus::Ok && result.durability == Durability::Durable, "durable append");
        require(store.normalized(first).status == StoreStatus::IndexPending && store.search({}).events.empty(), "raw before indexing");
        require(store.index(first).status == StoreStatus::Ok, "index");
        require(store.set_hold(first, true) == StoreStatus::Ok, "hold");
        const auto second = store.append({binding, "ssh.service", redacted, JournalMode::Authentication, 101}); pending = second.id;
        require(second.status == StoreStatus::Ok, "pending append");
        prior_revision = store.search({}).revision;
        require(store.append({binding, "ssh.service", original, JournalMode::Unsupported, 100}).status == StoreStatus::Invalid, "unsupported mode");
        require(store.append({binding, "ssh.service", row("first", "ssh-failed"), JournalMode::Authentication, 101}).status == StoreStatus::Conflict, "conflicting retry");
        struct stat st{}; require(stat(f.db().c_str(), &st) == 0 && (st.st_mode & 0777) == 0600, "database permissions");
        // A separate read transaction blocks the writer's COMMIT, not merely BEGIN.
        External reader(f.db()); reader.sql("BEGIN; SELECT * FROM meta");
        const auto blocked = store.append({binding, "ssh.service", row("blocked"), JournalMode::Authentication, 102});
        require(blocked.status == StoreStatus::Unavailable && blocked.durability == Durability::None, "commit refusal");
        reader.sql("ROLLBACK");
        require(store.search({}).revision == prior_revision && store.pending(0, {}, 32).ids == std::vector<EventId>{pending}, "transaction rollback");
    }
    // Simulate the known v1 schema (same tables, no secondary indexes) with
    // genuine data, then exercise the transactional v1 -> v2 migration.
    { External db(f.db()); db.sql("BEGIN; DROP INDEX event_search; DROP INDEX event_binding; DROP INDEX event_retention; PRAGMA user_version=1; COMMIT"); }
    {
        SqliteEventStore store(f.path);
        const auto raw = store.raw(first); require(raw.value && raw.value->canonical_row == original && raw.value->held && raw.value->received_ms == 100, "restart evidence and hold");
        require(store.normalized(pending).status == StoreStatus::IndexPending && store.search({}).revision == prior_revision, "restart pending and revision");
        const auto retry = store.append({binding, "ssh.service", original, JournalMode::Authentication, 999});
        require(retry.status == StoreStatus::ExactRetry && retry.id == first, "restart retry");
        require(store.index(pending).status == StoreStatus::Ok, "replay index");
        SearchQuery q; q.class_uid = OcsfClass::Authentication; q.status_id = OcsfStatus::Success; q.binding = binding;
        const auto page = store.search(q); require(page.status == StoreStatus::Ok && page.events.size() == 1 && page.events[0].id == first, "filtered search");
        q.from_ms = page.events[0].time_ms; q.through_ms = q.from_ms; require(store.search(q).events.size() == 1, "inclusive time bounds");
        q.binding = std::string_view{}; q.status_id = OcsfStatus::Failure; require(store.search(q).events.empty(), "nonmatch");
        SearchQuery all; all.limit = 1; const auto one = store.search(all); require(one.more && one.events[0].id == first, "page one");
        all.after = first; all.revision = one.revision; require(store.search(all).events[0].id == pending, "page two");
        const auto plan = store.preview_retention(102, 32); require(plan.plan && plan.plan->ids == std::vector<EventId>{pending}, "hold exclusion");
        auto altered = *plan.plan; altered.ids[0] = first; require(store.apply_retention(altered).status == StoreStatus::Invalid, "forged plan");
        require(store.set_hold(pending, true) == StoreStatus::Ok && store.apply_retention(*plan.plan).status == StoreStatus::Stale && store.search(all).status == StoreStatus::Stale, "stale plan and page");
        require(store.set_hold(pending, false) == StoreStatus::Ok, "release hold");
        const auto next = store.preview_retention(102, 32); require(next.plan && store.apply_retention(*next.plan).removed == 1, "retention commit");
        require(store.raw(pending).status == StoreStatus::NotFound, "retained evidence removed");
    }
    // Abrupt termination after a successful commit: no normal SQLite close.
    const auto pid = fork(); require(pid >= 0, "fork");
    if (pid == 0) {
        try {
            SqliteEventStore store(f.path);
            const auto r = store.append({binding, "ssh.service", redacted, JournalMode::Authentication, 103});
            _exit(r.status == StoreStatus::Ok && r.id > pending ? 0 : 1);
        } catch (...) { _exit(2); }
    }
    int status{}; require(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "abrupt child commit");
    {
        SqliteEventStore store(f.path);
        const auto p = store.pending(0, {}, 32); require(p.ids.size() == 1 && p.ids[0] > pending, "restart after abrupt termination");
        for (std::size_t n = 2; n < SqliteEventStore::max_records; ++n) {
            require(store.append({binding, "ssh.service", row("fill-" + std::to_string(n)), JournalMode::Authentication, 200}).status == StoreStatus::Ok, "capacity fill");
        }
        require(store.append({binding, "ssh.service", row("extra"), JournalMode::Authentication, 200}).status == StoreStatus::Capacity, "bounded capacity");
        require(store.append({binding, "ssh.service", original, JournalMode::Authentication, 200}).status == StoreStatus::ExactRetry, "retry at capacity");
        require(chmod(f.path.c_str(), 0755) == 0, "fixture chmod");
        require(store.raw(first).status == StoreStatus::Unavailable, "runtime permission rejection");
        require(chmod(f.path.c_str(), 0700) == 0, "restore fixture permissions");
    }
    { External db(f.db()); db.sql("PRAGMA user_version=999"); }
    require(rejects(f.path), "future schema rejected");
    { External db(f.db()); db.sql("PRAGMA user_version=2; UPDATE events SET status_id=2 WHERE id=1"); }
    require(rejects(f.path), "inconsistent indexed projection rejected");
    { External db(f.db()); db.sql("UPDATE events SET status_id=1 WHERE id=1; PRAGMA ignore_check_constraints=ON; UPDATE events SET mode=99 WHERE id=1"); }
    require(rejects(f.path), "unknown stored enum rejected");
    // All canonical profiles, distinct endpoint identity, bounded queries and
    // pending retention behavior are checked against a separate fresh store.
    Fixture profiles;
    {
        SqliteEventStore store(profiles.path);
        const auto base = "native-cursor\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' + std::string(32, 'd') + '\t';
        const auto metadata = base + "fixture.service\n";
        const auto audit = base + "audit\t1100\t9\n";
        const auto other = std::string(32, 'e') + std::string(64, 'b');
        const auto m = store.append({binding, "fixture.service", metadata, JournalMode::Metadata, 10});
        const auto a = store.append({other, "audit", audit, JournalMode::Audit, 11});
        require(m.status == StoreStatus::Ok && a.status == StoreStatus::Ok && m.id != a.id, "endpoint-scoped native cursor");
        require(store.append({binding, "fixture.service", "invalid", JournalMode::Metadata, 10}).status == StoreStatus::Invalid, "invalid row");
        require(store.append({binding, "fixture.service", metadata, JournalMode::Metadata, 0}).status == StoreStatus::Invalid, "invalid receipt time");
        const auto first_page = store.pending(0, {}, 1);
        require(first_page.more && first_page.ids == std::vector<EventId>{m.id}, "pending page one");
        require(store.pending(m.id, first_page.revision, 1).ids == std::vector<EventId>{a.id}, "pending page two");
        require(store.index(m.id).status == StoreStatus::Ok && store.pending(m.id, first_page.revision, 1).status == StoreStatus::Stale, "pending revision invalidation");
        const auto plan = store.preview_retention(12, 32);
        require(plan.plan && plan.plan->ids == std::vector<EventId>{m.id}, "pending retention exclusion");
        require(store.index(a.id).status == StoreStatus::Ok, "audit index");
        const auto native = store.normalized(a.id);
        require(native.value && native.value->source.audit_type == 1100 && native.value->source.audit_id == 9 && native.value->mapping == MappingResult::AuditTypeUnmapped, "audit provenance");
        SearchQuery q; q.binding = other; q.class_uid = OcsfClass::Base;
        const auto page = store.search(q); require(page.events.size() == 1 && page.events[0].id == a.id, "binding and class filters");
        q.limit = 33; require(store.search(q).status == StoreStatus::Invalid, "query bound");
        q.limit = 1; q.binding = "' OR 1=1 --"; require(store.search(q).status == StoreStatus::Invalid, "invalid query binding");
        require(store.apply_retention(*plan.plan).status == StoreStatus::Stale, "index invalidates retention plan");
        const auto cutoff = store.preview_retention(11, 32);
        require(cutoff.plan && cutoff.plan->ids == std::vector<EventId>{m.id}, "strict receipt cutoff");
    }
    // Interrupt an actual uncommitted write after flushing dirty pages; SQLite
    // must recover the rollback journal and preserve the prior committed value.
    const auto crash = fork(); require(crash >= 0, "fixture crash fork");
    if (crash == 0) {
        try {
            External db(profiles.db()); db.sql("PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; BEGIN IMMEDIATE; UPDATE events SET held=1 WHERE id=1");
            _exit(sqlite3_db_cacheflush(db.db) == SQLITE_OK ? 0 : 1);
        } catch (...) { _exit(2); }
    }
    int crashed{}; require(waitpid(crash, &crashed, 0) == crash && WIFEXITED(crashed) && WEXITSTATUS(crashed) == 0, "uncommitted fixture write");
    { SqliteEventStore store(profiles.path); const auto raw = store.raw(1); require(raw.value && !raw.value->held, "hot rollback recovery"); }
    { External db(profiles.db()); db.sql("PRAGMA application_id=17"); }
    require(rejects(profiles.path), "foreign application ID rejected");
    Fixture unsafe;
    require(symlink(f.db().c_str(), unsafe.db().c_str()) == 0 && rejects(unsafe.path), "database symlink rejected");
    require(rejects("relative") && rejects(unsafe.path + "/missing"), "no fallback directory");
    Fixture journal;
    require(symlink(f.db().c_str(), (journal.db()+"-journal").c_str()) == 0 && rejects(journal.path), "journal symlink rejected");
    require(chmod(unsafe.path.c_str(), 0755) == 0 && rejects(unsafe.path), "unsafe directory rejected");
}
} // namespace
int main() {
    umask(0077);
    try { verify(); std::cout << "M6.4 SQLite restart, migrations, transactional rollback, indexed queries and enum validation: PASS\n"; return 0; }
    catch (const std::exception& e) { std::cerr << "M6.4: " << e.what() << '\n'; return 1; }
}

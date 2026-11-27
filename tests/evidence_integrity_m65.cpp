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
        char name[] = "/var/tmp/ks-m65-XXXXXX";
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
bool rejects(const std::string& path, LegacyIntegrityPolicy policy = LegacyIntegrityPolicy::Reject) {
    try { SqliteEventStore store(path, policy); } catch (const std::runtime_error&) { return true; }
    return false;
}
std::string row(std::string_view cursor, std::string_view suffix = "ssh-accepted") {
    return std::string(cursor) + "\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + "\tssh.service\t" + std::string(suffix) + '\n';
}
void verify() {
    const auto binding = std::string(32, 'a') + std::string(64, 'b');
    const auto wire = row("fixture");
    constexpr std::string_view expected = "1e87f1bd9d1d2f02ed52f3fe3099af7d8503b41d61d1c80b2b123205d71ae0e4";
    constexpr std::string_view legacy = "0660600b56f361b808013c766e71d0a5d69f8a7d3aa3bcd4c84831de84293789";
    const RawInput input{binding, "ssh.service", wire, JournalMode::Authentication, 100};
    Fixture f;
    {
        SqliteEventStore store(f.path);
        const auto added = store.append(input); require(added.status == StoreStatus::Ok && added.id == 1, "admission");
        const auto original = store.raw(1);
        require(original.value && original.value->integrity && original.value->integrity->sha256 == expected &&
            original.value->integrity->origin == IntegrityOrigin::Admission && original.value->canonical_row == wire, "independent SHA256 fixture");
        require(store.index(1).status == StoreStatus::Ok && store.set_hold(1, true) == StoreStatus::Ok, "index and hold");
        const auto retry = store.append({binding, "ssh.service", wire, JournalMode::Authentication, 900});
        require(retry.status == StoreStatus::ExactRetry && retry.id == 1, "retry");
        const auto unchanged = store.raw(1);
        require(unchanged.value && unchanged.value->integrity && unchanged.value->integrity->sha256 == expected && unchanged.value->received_ms == 100, "commitment immutable");
    }
    { SqliteEventStore store(f.path); const auto v = store.raw(1); require(v.value && v.value->integrity && v.value->integrity->sha256 == expected, "restart commitment"); }
    // Valid canonical alteration with unchanged normalized milliseconds.
    {
        SqliteEventStore store(f.path);
        { External db(f.db()); db.sql("UPDATE events SET wire=replace(wire,'1795000000123456','1795000000123457') WHERE id=1"); }
        SearchQuery excluded; excluded.status_id = OcsfStatus::Failure;
        require(store.raw(1).status == StoreStatus::IntegrityFailure && store.normalized(1).status == StoreStatus::IntegrityFailure, "read tamper rejection");
        require(store.search(excluded).status == StoreStatus::IntegrityFailure && store.pending(0, {}, 32).status == StoreStatus::IntegrityFailure, "filtered tamper rejection");
        require(store.append(input).status == StoreStatus::IntegrityFailure && store.index(1).status == StoreStatus::IntegrityFailure && store.set_hold(1, false) == StoreStatus::IntegrityFailure, "mutation tamper rejection");
        require(store.preview_retention(200, 32).status == StoreStatus::IntegrityFailure && store.apply_retention({1, 200, 32, {1}}).status == StoreStatus::IntegrityFailure, "retention tamper rejection");
    }
    require(rejects(f.path), "restart detects changed evidence");
    for (const auto* sql : {
        "UPDATE events SET received=101 WHERE id=1",
        "UPDATE events SET wire=replace(wire,'ssh-accepted','ssh-failed') WHERE id=1",
        "UPDATE events SET wire=replace(wire,'1795000000123456','1795000000123457') WHERE id=1",
        "UPDATE events SET binding=substr(binding,1,32)||replace(substr(binding,33),'b','e') WHERE id=1",
        "UPDATE evidence_integrity SET sha256=printf('%064d',0) WHERE id=1",
        "UPDATE evidence_integrity SET origin=0 WHERE id=1",
        "DELETE FROM evidence_integrity WHERE id=1",
        "DELETE FROM events WHERE id=1",
        "DROP TABLE evidence_integrity"}) {
        Fixture corrupt;
        { SqliteEventStore store(corrupt.path); require(store.append(input).status == StoreStatus::Ok, "tamper fixture append"); }
        { External db(corrupt.db()); db.sql(sql); }
        require(rejects(corrupt.path), "corrupt store rejected");
    }
    // Simulate actual v2 schema, without integrity metadata.
    Fixture migrated;
    { SqliteEventStore store(migrated.path); require(store.append(input).status == StoreStatus::Ok, "legacy fixture"); }
    { External db(migrated.db()); db.sql("BEGIN; DROP TABLE evidence_integrity; PRAGMA user_version=2; COMMIT"); }
    require(rejects(migrated.path), "legacy migration requires explicit approval");
    {
        SqliteEventStore store(migrated.path, LegacyIntegrityPolicy::EstablishBaseline);
        const auto v = store.raw(1);
        require(v.value && v.value->integrity && v.value->integrity->origin == IntegrityOrigin::LegacyBaseline && v.value->integrity->sha256 == legacy, "legacy baseline");
        require(store.index(1).status == StoreStatus::Ok, "legacy indexing");
        const auto plan = store.preview_retention(101, 32);
        require(plan.plan && store.apply_retention(*plan.plan).removed == 1, "retention cascade");
        require(store.raw(1).status == StoreStatus::NotFound && store.search({}).status == StoreStatus::Ok, "no orphan digest");
        require(store.append(input).status == StoreStatus::Ok, "new admission after retention");
        const auto fresh = store.raw(2);
        require(fresh.value && fresh.value->integrity && fresh.value->integrity->origin == IntegrityOrigin::Admission && fresh.value->integrity->sha256 != legacy, "new commitment");
    }
    { SqliteEventStore store(migrated.path); require(store.raw(2).status == StoreStatus::Ok, "restart after retention"); }
    Fixture broken;
    { SqliteEventStore store(broken.path); require(store.append(input).status == StoreStatus::Ok, "broken legacy fixture"); }
    { External db(broken.db()); db.sql("BEGIN; DROP TABLE evidence_integrity; PRAGMA user_version=2; UPDATE events SET wire='invalid' WHERE id=1; COMMIT"); }
    require(rejects(broken.path, LegacyIntegrityPolicy::EstablishBaseline), "invalid legacy rejected");
    { External db(broken.db());
        sqlite3_stmt* stmt{}; require(sqlite3_prepare_v2(db.db, "PRAGMA user_version", -1, &stmt, nullptr) == SQLITE_OK, "schema version query");
        const bool version_ok = sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 2;
        sqlite3_finalize(stmt); require(version_ok, "failed migration preserves version"); }
    MemoryEventStore memory;
    require(memory.append(input).status == StoreStatus::Ok, "volatile fixture");
    const auto v = memory.raw(1); require(v.value && !v.value->integrity, "volatile not falsely committed");
}
} // namespace
int main() {
    umask(0077);
    try { verify(); std::cout << "M6.5 original evidence SHA-256, migration baseline, tamper rejection and retention: PASS\n"; return 0; }
    catch (const std::exception& e) { std::cerr << "M6.5: " << e.what() << '\n'; return 1; }
}

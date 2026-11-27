// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/storage/sqlite_event_store.hpp>
#include <sqlite3.h>
#include <cstdlib>
#include <sys/stat.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace {
using namespace knetsentry::storage;
using knetsentry::agent::JournalMode;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
class Fixture final {
public:
    Fixture() { char name[] = "/var/tmp/ks-m67-XXXXXX"; const auto* p = mkdtemp(name); require(p != nullptr, "fixture"); path = p; }
    ~Fixture() { std::error_code ec; std::filesystem::remove_all(path, ec); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    std::string path;
};
std::string wire(EventId id, std::size_t padding = 0) {
    return "cursor-" + std::to_string(id) + std::string(padding, 'x') + "\t1795000000123456\t42\t" +
        std::string(32, 'c') + '\t' + std::string(32, 'd') + "\tssh.service\tssh-failed\n";
}
AppendResult add(EventStore& store, EventId id, std::uint64_t received, std::size_t padding = 0) {
    const auto binding = std::string(32, 'a') + std::string(64, 'b');
    return store.append({binding, "ssh.service", wire(id, padding), JournalMode::Authentication, received});
}
StorageUsage usage(EventStore& store) {
    const auto result = store.usage(); require(result.status == StoreStatus::Ok && result.value.has_value(), "usage"); return *result.value;
}
RetentionPlan plan(EventStore& store, std::uint64_t now) {
    const auto result = store.preview_cleanup(now); require(result.status == StoreStatus::Ok && result.plan.has_value(), "preview"); return *result.plan;
}
StoragePolicy policy() {
    StoragePolicy p; p.record_limit = 4; p.warning_percent = 75; p.retention_ms = 100; p.cleanup_batch = 1; return p;
}
void exercise(EventStore& store) {
    require(usage(store).records == 0, "empty");
    for (EventId id = 1; id <= 4; ++id) {
        require(add(store, id, id == 4 ? 100U : 99U).status == StoreStatus::Ok, "admission");
        if (id != 3) { require(store.index(id).status == StoreStatus::Ok, "index"); }
        if (id == 2) { require(store.set_hold(id, true) == StoreStatus::Ok, "hold"); }
        require(usage(store).record_warning == (id >= 3), "warning threshold");
    }
    const auto full = usage(store);
    require(full.records == 4 && full.held == 1 && full.pending == 1 && full.wire_bytes == 4 * wire(1).size(), "aggregate counts");
    require(add(store, 5, 100).status == StoreStatus::Capacity && usage(store).records == 4, "quota must not evict");
    require(add(store, 1, 200).status == StoreStatus::ExactRetry, "retry at quota");
    require(plan(store, 50).ids.empty(), "clock underflow");
    auto cleanup = plan(store, 200);
    require(cleanup.ids == std::vector<EventId>{1}, "held pending and exact cutoff protected");
    auto forged = cleanup; forged.ids = {2}; require(store.apply_cleanup(200, forged).status == StoreStatus::Invalid, "forged plan");
    require(store.apply_cleanup(201, cleanup).status == StoreStatus::Invalid, "changed clock");
    require(store.set_hold(1, true) == StoreStatus::Ok, "hold mutation");
    require(store.apply_cleanup(200, cleanup).status == StoreStatus::Stale, "stale cleanup");
    require(store.set_hold(1, false) == StoreStatus::Ok, "release hold");
    cleanup = plan(store, 200);
    const auto removed = store.apply_cleanup(200, cleanup);
    require(removed.status == StoreStatus::Ok && removed.removed == 1 && usage(store).records == 3, "explicit cleanup");
    const auto held = store.raw(2);
    require(store.raw(1).status == StoreStatus::NotFound && held.value && held.value->held && store.raw(3).status == StoreStatus::Ok, "survivors");
    require(store.apply_cleanup(200, cleanup).status == StoreStatus::Stale, "replayed cleanup");
    require(plan(store, 200).ids.empty(), "no eligible evidence");
    const auto next = add(store, 5, 101); require(next.status == StoreStatus::Ok && next.id == 5, "recovered capacity and monotonic ID");
}
void byte_limit(EventStore& store) {
    require(add(store, 1, 99).status == StoreStatus::Ok, "wire admission");
    const auto u = usage(store); require(u.wire_warning && u.wire_bytes == wire(1).size(), "wire warning");
    require(add(store, 2, 99).status == StoreStatus::Capacity, "wire quota");
    require(add(store, 1, 100).status == StoreStatus::ExactRetry, "wire exact retry");
    require(store.index(1).status == StoreStatus::Ok, "wire full indexing");
    require(store.apply_cleanup(200, plan(store, 200)).removed == 1, "wire recovery");
    require(!usage(store).wire_warning && add(store, 2, 101).status == StoreStatus::Ok, "wire recovery admission");
}
void disk_limit() {
    Fixture fixture;
    StoragePolicy p; p.database_page_limit = 16; p.warning_percent = 1;
    std::size_t admitted = 0;
    {
        SqliteEventStore store(fixture.path, LegacyIntegrityPolicy::Reject, p);
        const auto first = usage(store); require(first.disk && first.disk->warning, "disk warning");
        for (EventId id = 1; id <= 128; ++id) {
            const auto r = add(store, id, 99, 900);
            if (r.status == StoreStatus::Capacity) { break; }
            require(r.status == StoreStatus::Ok, "disk admission"); ++admitted;
        }
        const auto full = usage(store);
        require(admitted > 0 && admitted < 128 && full.records == admitted, "physical page cap and rollback");
        require(full.disk && full.disk->allocated_pages <= p.database_page_limit, "page cap");
        require(add(store, 1, 100, 900).status == StoreStatus::ExactRetry, "physical cap retry");
    }
    require(std::filesystem::file_size(fixture.path + "/events-m64.sqlite3") <= p.database_page_limit * StoragePolicy::page_bytes, "file cap");
    SqliteEventStore reopened(fixture.path, LegacyIntegrityPolicy::Reject, p);
    require(usage(reopened).records == admitted, "disk restart");
}
void cleanup_rollback() {
    Fixture fixture;
    SqliteEventStore store(fixture.path, LegacyIntegrityPolicy::Reject, policy());
    require(add(store, 1, 99).status == StoreStatus::Ok && store.index(1).status == StoreStatus::Ok, "rollback fixture");
    const auto cleanup = plan(store, 200);
    sqlite3* reader{};
    const auto rc = sqlite3_open_v2((fixture.path + "/events-m64.sqlite3").c_str(), &reader, SQLITE_OPEN_READWRITE, nullptr);
    if (rc != SQLITE_OK) { sqlite3_close(reader); throw std::runtime_error("reader open"); }
    const auto begin = sqlite3_exec(reader, "BEGIN; SELECT * FROM meta", nullptr, nullptr, nullptr);
    if (begin != SQLITE_OK) { sqlite3_close(reader); throw std::runtime_error("reader lock"); }
    const auto blocked = store.apply_cleanup(200, cleanup);
    sqlite3_close(reader);
    require(blocked.status == StoreStatus::Unavailable && blocked.removed == 0, "cleanup commit refusal");
    const auto raw = store.raw(1);
    require(raw.status == StoreStatus::Ok && raw.value && raw.value->integrity && plan(store, 200).revision == cleanup.revision, "cleanup rollback preserves evidence and revision");
    require(store.apply_cleanup(200, cleanup).removed == 1 && usage(store).records == 0, "cleanup retry");
}
void page_reuse() {
    Fixture fixture;
    StoragePolicy p; p.database_page_limit = 128; p.retention_ms = 100;
    SqliteEventStore store(fixture.path, LegacyIntegrityPolicy::Reject, p);
    for (EventId id = 1; id <= 20; ++id) {
        require(add(store, id, 99, 900).status == StoreStatus::Ok && store.index(id).status == StoreStatus::Ok, "reuse fixture");
    }
    const auto before = usage(store);
    require(store.apply_cleanup(200, plan(store, 200)).removed == 20, "bounded disk cleanup");
    const auto after = usage(store);
    require(before.disk && after.disk && after.disk->allocated_pages == before.disk->allocated_pages &&
        after.disk->reusable_pages > before.disk->reusable_pages, "freelist not file shrink");
    require(add(store, 21, 101, 900).status == StoreStatus::Ok, "reuse admission");
    const auto reused = usage(store);
    require(reused.disk && reused.disk->allocated_pages == after.disk->allocated_pages, "reuse without growth");
}
void corruption() {
    Fixture fixture;
    SqliteEventStore store(fixture.path, LegacyIntegrityPolicy::Reject, policy());
    require(add(store, 1, 99).status == StoreStatus::Ok && store.index(1).status == StoreStatus::Ok, "tamper fixture");
    const auto cleanup = plan(store, 200);
    sqlite3* db{};
    const auto rc = sqlite3_open_v2((fixture.path + "/events-m64.sqlite3").c_str(), &db, SQLITE_OPEN_READWRITE, nullptr);
    if (rc != SQLITE_OK) { sqlite3_close(db); throw std::runtime_error("tamper open"); }
    const auto update = sqlite3_exec(db, "UPDATE evidence_integrity SET sha256=printf('%064d',0)", nullptr, nullptr, nullptr);
    sqlite3_close(db); require(update == SQLITE_OK, "tamper update");
    require(store.usage().status == StoreStatus::IntegrityFailure && store.preview_cleanup(200).status == StoreStatus::IntegrityFailure &&
        store.apply_cleanup(200, cleanup).status == StoreStatus::IntegrityFailure, "tamper refusal");
}
} // namespace
int main() try {
    umask(0077);
    StoragePolicy bad; bad.record_limit = 0; require(!valid_storage_policy(bad), "zero limit");
    bad = {}; bad.database_page_limit = 2049; require(!valid_storage_policy(bad), "large disk limit");
    bad = {}; bad.warning_percent = 101; require(!valid_storage_policy(bad), "warning bounds");
    bad = {}; bad.cleanup_batch = 33; require(!valid_storage_policy(bad), "batch bounds");
    bad = {}; bad.wire_byte_limit = 0; require(!valid_storage_policy(bad), "wire bounds");
    bool rejected = false; try { MemoryEventStore invalid(bad); } catch (const std::invalid_argument&) { rejected = true; }
    require(rejected, "invalid constructor");
    MemoryEventStore disabled; require(disabled.preview_cleanup(200).status == StoreStatus::Invalid, "disabled default");
    MemoryEventStore memory(policy()); exercise(memory); require(!usage(memory).disk, "volatile no disk metrics");
    Fixture fixture;
    {
        SqliteEventStore sqlite(fixture.path, LegacyIntegrityPolicy::Reject, policy()); exercise(sqlite);
        require(usage(sqlite).disk.has_value(), "SQLite disk metrics");
    }
    auto lower = policy(); lower.record_limit = 2;
    SqliteEventStore restarted(fixture.path, LegacyIntegrityPolicy::Reject, lower);
    require(usage(restarted).records == 4 && add(restarted, 6, 102).status == StoreStatus::Capacity, "reopen lower logical quota retains evidence");
    auto bytes = policy(); bytes.wire_byte_limit = wire(1).size();
    MemoryEventStore byte_memory(bytes); byte_limit(byte_memory);
    Fixture byte_fixture; SqliteEventStore byte_sqlite(byte_fixture.path, LegacyIntegrityPolicy::Reject, bytes); byte_limit(byte_sqlite);
    disk_limit(); cleanup_rollback(); page_reuse(); corruption();
    std::cout << "M6.7 configured retention, quotas, warnings, protected cleanup and disk rollback: PASS\n";
    return 0;
} catch (const std::exception& error) { std::cerr << "M6.7: " << error.what() << '\n'; return 1; }

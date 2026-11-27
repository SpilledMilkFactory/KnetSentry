// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/storage/sqlite_event_store.hpp>
#include <sqlite3.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <array>
#include <memory>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
using namespace knetsentry::storage;
using knetsentry::agent::JournalMode;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
class Fixture final {
public:
    Fixture() {
        char name[] = "/var/tmp/ks-m69-XXXXXX";
        const auto* p = mkdtemp(name); require(p != nullptr, "fixture directory"); path = p;
    }
    ~Fixture() { std::error_code ec; std::filesystem::remove_all(path, ec); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    std::string path;
    [[nodiscard]] std::string db() const { return path + "/events-m64.sqlite3"; }
};
class External final {
public:
    explicit External(const Fixture& f) {
        if (sqlite3_open_v2(f.db().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
            sqlite3_close(db); throw std::runtime_error("fixture database");
        }
    }
    ~External() { sqlite3_close(db); }
    External(const External&) = delete;
    External& operator=(const External&) = delete;
    void sql(const char* text) { require(sqlite3_exec(db, text, nullptr, nullptr, nullptr) == SQLITE_OK, "fixture SQL"); }
    [[nodiscard]] int scalar(const char* text) {
        sqlite3_stmt* raw{};
        const auto rc = sqlite3_prepare_v2(db, text, -1, &raw, nullptr);
        const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(raw, sqlite3_finalize);
        require(rc == SQLITE_OK && sqlite3_step(stmt.get()) == SQLITE_ROW, "fixture scalar");
        return sqlite3_column_int(stmt.get(), 0);
    }
    sqlite3* db{};
};
std::string wire(std::string_view cursor, std::string_view time = "1795000000123456", std::string_view category = "ssh-failed") {
    return std::string(cursor) + '\t' + std::string(time) + "\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + "\tssh.service\t" + std::string(category) + '\n';
}
AppendResult add(EventStore& store, std::string_view row, std::uint64_t received) {
    return store.append({std::string(96, 'a'), "ssh.service", row, JournalMode::Authentication, received});
}
std::uint64_t revision(EventStore& store) {
    const auto page = store.search({}); require(page.status == StoreStatus::Ok, "search status"); return page.revision;
}
void unchanged(EventStore& store, std::uint64_t rev, const std::string& digest) {
    const auto raw = store.raw(1);
    require(raw.status == StoreStatus::Ok && raw.value && raw.value->canonical_row == wire("committed") &&
        raw.value->received_ms == 100 && raw.value->held && raw.value->integrity && raw.value->integrity->sha256 == digest &&
        raw.value->integrity->origin == IntegrityOrigin::Admission, "committed evidence changed");
    const auto page = store.search({});
    require(page.status == StoreStatus::Ok && page.revision == rev && page.events.size() == 1 && page.events.front().id == 1,
        "committed projection/revision changed");
    const auto pending = store.pending(0, {}, 32);
    require(pending.status == StoreStatus::Ok && pending.ids == std::vector<EventId>{2}, "pending state changed");
    const auto u = store.usage(); require(u.status == StoreStatus::Ok && u.value && u.value->records == 2, "unexpected record count");
}
int child_status(pid_t pid) {
    int status{}; pid_t result{};
    do { result = waitpid(pid, &status, 0); } while (result < 0 && errno == EINTR);
    require(result == pid, "wait child"); return status;
}
bool rejects(const Fixture& f, LegacyIntegrityPolicy policy = LegacyIntegrityPolicy::Reject) {
    try { SqliteEventStore store(f.path, policy); } catch (const std::runtime_error&) { return true; }
    return false;
}
void timestamp_contract(EventStore& store) {
    const auto initial = revision(store);
    for (const auto stamp : {"0", "01", "-1", "+1", "1x", "36028797018963968", "18446744073709551616"}) {
        const auto result = add(store, wire("invalid", stamp), 100);
        require(result.status == StoreStatus::Invalid && result.id == 0 && result.durability == Durability::None, "invalid source timestamp admitted");
    }
    for (const auto received : {std::uint64_t{0}, std::numeric_limits<std::uint64_t>::max()}) {
        require(add(store, wire("invalid"), received).status == StoreStatus::Invalid, "invalid receiver timestamp admitted");
    }
    for (const auto& row : {std::string("malformed\n"), wire("invalid") + wire("extra"), wire("invalid", "1", "private-message"), std::string(2049, 'x')}) {
        require(add(store, row, 100).status == StoreStatus::Invalid, "malformed record admitted");
    }
    require(revision(store) == initial && store.search({}).events.empty(), "invalid input changed storage");
    const auto future = wire("future", "36028797018963967");
    const auto old = wire("old", "1");
    const auto a = add(store, future, 100); const auto b = add(store, old, 200);
    require(a.status == StoreStatus::Ok && a.id == 1 && b.status == StoreStatus::Ok && b.id == 2, "boundary admissions");
    require(store.index(a.id).status == StoreStatus::Ok && store.index(b.id).status == StoreStatus::Ok, "boundary index");
    const auto normalized = store.normalized(b.id);
    require(normalized.status == StoreStatus::Ok && normalized.value && normalized.value->time_ms == 0 &&
        normalized.value->source.realtime_usec == 1, "sub-ms timestamp lost");
    SearchQuery query; query.from_ms = 36028797018963ULL; query.through_ms = query.from_ms;
    const auto page = store.search(query);
    require(page.status == StoreStatus::Ok && page.events.size() == 1 && page.events.front().id == a.id &&
        page.events.front().received_ms == 100, "future source-time search");
    const auto plan = store.preview_retention(150, 32);
    require(plan.status == StoreStatus::Ok && plan.plan && plan.plan->ids == std::vector<EventId>{a.id}, "source timestamp controlled retention");
    const auto rev = revision(store);
    const auto retry = add(store, future, 999);
    require(retry.status == StoreStatus::ExactRetry && retry.id == a.id && revision(store) == rev, "retry changed revision");
    require(add(store, wire("future", "1"), 999).status == StoreStatus::Conflict && revision(store) == rev, "timestamp conflict changed storage");
    const auto saved = store.raw(a.id); require(saved.value && saved.value->received_ms == 100, "retry changed receiver time");
}
void recovery() {
    Fixture f;
    std::uint64_t rev{}; std::string digest;
    {
        SqliteEventStore store(f.path);
        require(add(store, wire("committed"), 100).status == StoreStatus::Ok && store.index(1).status == StoreStatus::Ok &&
            store.set_hold(1, true) == StoreStatus::Ok && add(store, wire("pending"), 101).status == StoreStatus::Ok, "baseline setup");
        const auto raw = store.raw(1); require(raw.value && raw.value->integrity, "baseline digest");
        digest = raw.value->integrity->sha256; rev = revision(store);
        // External competing writer blocks BEGIN, rather than COMMIT.
        External lock(f); lock.sql("BEGIN IMMEDIATE");
        const auto blocked = add(store, wire("blocked"), 102);
        require(blocked.status == StoreStatus::Unavailable && blocked.id == 0 && blocked.durability == Durability::None, "busy writer acknowledged");
        require(store.index(2).status == StoreStatus::Unavailable, "busy index acknowledged");
        lock.sql("ROLLBACK"); unchanged(store, rev, digest);
    }
    // Deliberately interrupt an external SQLite transaction after cache flush.
    // This is a real hot-journal recovery test, not a claim of a precise
    // production EventStore crash point or power-loss simulation.
    const auto crash = fork(); require(crash >= 0, "fork hot journal");
    if (crash == 0) {
        try {
            External writer(f);
            writer.sql("PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; BEGIN IMMEDIATE; UPDATE events SET held=0 WHERE id=1; UPDATE meta SET revision=revision+1,next_id=next_id+1");
            require(sqlite3_db_cacheflush(writer.db) == SQLITE_OK, "flush uncommitted pages");
            std::ifstream journal(f.db() + "-journal", std::ios::binary);
            std::array<unsigned char, 8> header{};
            journal.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
            constexpr std::array<unsigned char, 8> magic{0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7};
            require(journal && header == magic, "hot journal header");
            static_cast<void>(kill(getpid(), SIGKILL));
        } catch (...) { _exit(2); }
        _exit(3);
    }
    const auto status = child_status(crash);
    require(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL && std::filesystem::exists(f.db() + "-journal"), "interrupted write not reached");
    { SqliteEventStore store(f.path); unchanged(store, rev, digest); }
    // Force an actual file-write failure in an isolated child. The limit is
    // applied only after opening the store, never to the parent or host disk.
    const auto limited = fork(); require(limited >= 0, "fork file limit");
    if (limited == 0) {
        try {
            SqliteEventStore store(f.path);
            struct sigaction action{}; action.sa_handler = SIG_IGN;
            require(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGXFSZ, &action, nullptr) == 0, "file limit signal");
            struct rlimit limit{}; require(getrlimit(RLIMIT_FSIZE, &limit) == 0, "read file limit");
            limit.rlim_cur = 0; require(setrlimit(RLIMIT_FSIZE, &limit) == 0, "set file limit");
            const auto failed = add(store, wire("limited"), 102);
            _exit((failed.status == StoreStatus::IoError || failed.status == StoreStatus::Capacity) && failed.id == 0 &&
                failed.durability == Durability::None ? 0 : 4);
        } catch (...) { _exit(2); }
    }
    const auto limited_status = child_status(limited);
    require(WIFEXITED(limited_status) && WEXITSTATUS(limited_status) == 0, "file limit failure not observed");
    { SqliteEventStore store(f.path); unchanged(store, rev, digest); }
    // Start from a genuine populated v3 schema. A competing reader permits
    // BEGIN IMMEDIATE but blocks migration COMMIT. No new indexes may survive.
    { External db(f); db.sql("BEGIN; DROP INDEX event_mode; DROP INDEX event_source; DROP INDEX event_time; PRAGMA user_version=3; COMMIT"); }
    {
        External reader(f); reader.sql("BEGIN; SELECT * FROM meta");
        require(rejects(f), "blocked migration activated");
        reader.sql("ROLLBACK");
        require(reader.scalar("PRAGMA user_version") == 3 && reader.scalar("SELECT count(*) FROM sqlite_schema WHERE name IN ('event_mode','event_source','event_time')") == 0,
            "partial migration committed");
    }
    {
        SqliteEventStore store(f.path); unchanged(store, rev, digest);
        require(store.index(2).status == StoreStatus::Ok && add(store, wire("recovered"), 102).id == 3, "post-recovery next ID/index");
    }
    { External db(f); require(db.scalar("PRAGMA user_version") == 4, "migration retry version"); }
    // Physical SQLite page exhaustion within a disposable fixture, not ENOSPC.
    Fixture quota; StoragePolicy policy; policy.database_page_limit = 16;
    EventId last{};
    {
        SqliteEventStore store(quota.path, LegacyIntegrityPolicy::Reject, policy);
        for (EventId i = 1; i <= 128; ++i) {
            const auto row = wire("quota-" + std::to_string(i) + std::string(800, 'x'));
            const auto before = revision(store); const auto result = add(store, row, 100);
            if (result.status == StoreStatus::Capacity) {
                require(result.id == 0 && result.durability == Durability::None && revision(store) == before, "quota partial commit"); break;
            }
            require(result.status == StoreStatus::Ok && result.id == i, "quota fixture admission"); last = i;
        }
        require(last > 0 && last < 128, "page quota not reached");
    }
    {
        SqliteEventStore store(quota.path, LegacyIntegrityPolicy::Reject, policy);
        const auto u = store.usage(); require(u.value && u.value->records == last && u.value->disk && u.value->disk->allocated_pages <= 16, "quota restart");
        const auto retry = add(store, wire("quota-1" + std::string(800, 'x')), 999);
        require(retry.status == StoreStatus::ExactRetry && retry.id == 1 && retry.durability == Durability::Durable, "quota restart retry");
    }
}
} // namespace
int main() {
    try {
        static_cast<void>(umask(0077));
        MemoryEventStore memory; timestamp_contract(memory);
        Fixture f; SqliteEventStore store(f.path); timestamp_contract(store);
        std::cout << "M6.9 malformed records, timestamp boundaries, receipt-time retention and duplicate parity: PASS\n";
        recovery();
        std::cout << "M6.9 hot journal SIGKILL, write limit, busy writer, migration rollback and page quota recovery: PASS\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << "M6.9 storage recovery: FAIL: " << e.what() << '\n'; return 1; }
}

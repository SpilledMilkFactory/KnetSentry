// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/storage/split_event_store.hpp>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
using namespace knetsentry::storage;
namespace fs = std::filesystem;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
class Fixture final {
public:
    Fixture() {
        char pattern[] = "/var/tmp/ks-m610-XXXXXX";
        const auto* p = mkdtemp(pattern); require(p != nullptr, "fixture"); root = p;
        require(mkdir(raw().c_str(), 0700) == 0 && mkdir(index().c_str(), 0700) == 0, "directories");
    }
    ~Fixture() { std::error_code ec; fs::remove_all(root, ec); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    [[nodiscard]] std::string raw() const { return root + "/raw"; }
    [[nodiscard]] std::string index() const { return root + "/index"; }
    [[nodiscard]] SplitStorageConfig config() const {
        SplitStorageConfig c{inspect_storage_location(raw(), true), inspect_storage_location(index(), true)};
        c.policy.record_limit = 4; return c;
    }
    std::string root;
};
std::string wire(std::string_view cursor) {
    return std::string(cursor) + "\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + "\tssh.service\tssh-failed\n";
}
AppendResult append(SplitEventStore& store, std::string_view row, std::uint64_t received = 100) {
    return store.append({std::string(96, 'a'), "ssh.service", row, knetsentry::agent::JournalMode::Authentication, received});
}
bool rejected(const SplitStorageConfig& config, SplitOpenMode mode) {
    try { SplitEventStore store(config, mode); } catch (const std::runtime_error&) { return true; } return false;
}
void inspect_index(const Fixture& f) {
    sqlite3* db{};
    const auto rc = sqlite3_open_v2((f.index() + "/projection.sqlite3").c_str(), &db, SQLITE_OPEN_READONLY, nullptr);
    const std::unique_ptr<sqlite3, decltype(&sqlite3_close)> guard(db, sqlite3_close);
    require(rc == SQLITE_OK, "open persisted index");
    sqlite3_stmt* stmt{};
    const auto prepared = sqlite3_prepare_v2(db, "SELECT id,unit,status_id FROM projection ORDER BY id", -1, &stmt, nullptr);
    const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(stmt, sqlite3_finalize);
    require(prepared == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1 && sqlite3_column_int(stmt, 2) == 2 && sqlite3_step(stmt) == SQLITE_DONE, "persisted projection");
    std::ifstream file(f.index() + "/projection.sqlite3", std::ios::binary);
    std::string bytes; char byte{};
    while (file.get(byte)) { bytes.push_back(byte); }
    require(file.eof() && !file.bad(), "read persisted index");
    require(bytes.find("private-cursor") == bytes.npos && bytes.find(std::string(96, 'a')) == bytes.npos && bytes.find(wire("private-cursor")) == bytes.npos, "raw fields in index");
}
void exercise() {
    Fixture f; const auto c = f.config();
    auto invalid = c; ++invalid.raw.mount_id;
    require(rejected(invalid, SplitOpenMode::CreateNew), "mount mismatch");
    invalid = c; invalid.raw.boot_id = "wrong";
    require(rejected(invalid, SplitOpenMode::CreateNew), "boot mismatch");
    invalid = c; invalid.raw.filesystem_id[0] ^= 1;
    require(rejected(invalid, SplitOpenMode::CreateNew), "filesystem mismatch");
    invalid = c; invalid.index = c.raw;
    require(rejected(invalid, SplitOpenMode::CreateNew), "same directory");
    invalid = c; invalid.reserve_bytes = std::uint64_t{1} << 50U;
    require(rejected(invalid, SplitOpenMode::CreateNew) && fs::is_empty(f.raw()) && fs::is_empty(f.index()), "reserve refusal");
    require(rejected(c, SplitOpenMode::Existing), "implicit initialization");
    const auto alias = f.root + "/alias";
    require(symlink(f.raw().c_str(), alias.c_str()) == 0, "directory alias");
    try { static_cast<void>(inspect_storage_location(alias, true)); throw std::logic_error("directory symlink accepted"); }
    catch (const std::runtime_error&) { }
    fs::remove(alias);
    {
        SplitEventStore store(c, SplitOpenMode::CreateNew);
        require(rejected(c, SplitOpenMode::Existing), "concurrent ownership");
        require(append(store, "malformed").status == StoreStatus::Invalid, "invalid input");
        const auto first = append(store, wire("private-cursor"));
        require(first.status == StoreStatus::Ok && first.id == 1 && first.durability == Durability::Durable, "raw admission");
        require(store.search({}).status == StoreStatus::Ok && store.search({}).events.empty(), "premature visibility");
        require(store.pending(0, {}, 32).ids == std::vector<EventId>{1}, "pending raw");
        const auto original = store.raw(1); require(original.value && original.value->integrity && original.value->canonical_row == wire("private-cursor"), "raw provenance");
        require(store.index(1).status == StoreStatus::Ok && store.search({}).events.size() == 1, "publish index");
        inspect_index(f);
        require(append(store, wire("private-cursor"), 200).status == StoreStatus::ExactRetry && store.raw(1).value->received_ms == 100, "retry");
        fs::rename(f.index(), f.index() + "-saved"); require(mkdir(f.index().c_str(), 0700) == 0, "replacement index");
        const auto second = append(store, wire("pending")); require(second.id == 2 && second.durability == Durability::Durable, "raw survives index outage");
        require(store.index(2).durability == Durability::None && store.search({}).status != StoreStatus::Ok && fs::is_empty(f.index()), "index fallback");
        fs::remove(f.index()); fs::rename(f.index() + "-saved", f.index());
        require(store.pending(0, {}, 32).ids == std::vector<EventId>{2}, "restored pending");
        fs::rename(f.raw(), f.raw() + "-saved"); require(mkdir(f.raw().c_str(), 0700) == 0, "replacement raw");
        require(append(store, wire("blocked")).durability == Durability::None && store.search({}).status != StoreStatus::Ok && fs::is_empty(f.raw()), "raw fallback");
        fs::remove(f.raw()); fs::rename(f.raw() + "-saved", f.raw());
        require(chmod(f.raw().c_str(), 0755) == 0 && append(store, wire("blocked")).durability == Durability::None, "unsafe permissions");
        require(chmod(f.raw().c_str(), 0700) == 0, "restore permissions");
        require(symlink("/dev/null", (f.raw() + "/event-3.raw").c_str()) == 0, "symlink fixture");
        require(append(store, wire("blocked")).durability == Durability::None, "symlink accepted");
        fs::remove(f.raw() + "/event-3.raw");
    }
    require(rejected(c, SplitOpenMode::CreateNew), "implicit overwrite");
    {
        SplitEventStore store(c, SplitOpenMode::Existing);
        require(store.pending(0, {}, 32).ids == std::vector<EventId>{2}, "pending restart");
        require(store.index(2).status == StoreStatus::Ok && store.search({}).events.size() == 2, "pending replay");
        SearchQuery q; q.limit = 1; q.descending = true; const auto page = store.search(q);
        require(page.events.size() == 1 && page.events.front().id == 2 && page.more, "page");
        require(append(store, wire("third")).status == StoreStatus::Ok, "third raw");
        q.after = 2; q.revision = page.revision; require(store.search(q).status == StoreStatus::Stale, "stale page");
        require(append(store, wire("fourth")).status == StoreStatus::Ok && append(store, wire("full")).status == StoreStatus::Capacity, "quota");
        fs::remove(f.raw() + "/event-4.raw");
        require(append(store, wire("replacement")).status == StoreStatus::IntegrityFailure, "active suffix deletion");
    }
    { std::fstream file(f.raw() + "/event-1.raw", std::ios::in | std::ios::out | std::ios::binary); file.put('z'); }
    require(rejected(c, SplitOpenMode::Existing), "tampered raw accepted");
    std::cout << "M6.10 explicit placement, raw-first persistence, index outage, restart, quota and integrity: PASS\n";
}
void mount_fixture() {
    // Refuse before changing any mount unless a private namespace is available.
    require(unshare(CLONE_NEWNS) == 0 && mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == 0, "private mount namespace unavailable");
    Fixture f; const auto backing = f.root + "/backing";
    require(mkdir(backing.c_str(), 0700) == 0, "mount backing directory");
    require(mount(backing.c_str(), f.raw().c_str(), nullptr, MS_BIND, nullptr) == 0, "bind mount");
    try {
        const auto c = f.config(); SplitEventStore store(c, SplitOpenMode::CreateNew);
        require(append(store, wire("mounted")).status == StoreStatus::Ok, "mounted append");
        require(umount2(f.raw().c_str(), MNT_DETACH) == 0, "detach raw mount");
        require(append(store, wire("fallback")).durability == Durability::None && fs::is_empty(f.raw()), "unmount fallback");
        require(mount(backing.c_str(), f.raw().c_str(), nullptr, MS_BIND, nullptr) == 0, "new bind mount");
        require(append(store, wire("replacement")).durability == Durability::None, "new mount identity accepted");
        require(umount2(f.raw().c_str(), MNT_DETACH) == 0, "detach replacement mount");
    } catch (...) { static_cast<void>(umount2(f.raw().c_str(), MNT_DETACH)); throw; }
    std::cout << "M6.10 actual private bind mount detach, replacement and no fallback: PASS\n";
}
void index_integrity() {
    Fixture a; Fixture b; const auto ca = a.config(); const auto cb = b.config();
    { SplitEventStore store(ca, SplitOpenMode::CreateNew); require(append(store, wire("a")).status == StoreStatus::Ok && store.index(1).status == StoreStatus::Ok, "seed a"); }
    { SplitEventStore store(cb, SplitOpenMode::CreateNew); }
    auto wrong = ca; wrong.index = cb.index;
    require(rejected(wrong, SplitOpenMode::Existing), "wrong paired index");
    {
        SplitEventStore store(ca, SplitOpenMode::Existing);
        const auto db_path = a.index() + "/projection.sqlite3";
        sqlite3* db{}; const auto rc = sqlite3_open_v2(db_path.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr);
        const std::unique_ptr<sqlite3, decltype(&sqlite3_close)> guard(db, sqlite3_close);
        require(rc == SQLITE_OK && sqlite3_exec(db, "UPDATE projection SET status_id=1", nullptr, nullptr, nullptr) == SQLITE_OK, "tamper index fixture");
        require(store.search({}).status == StoreStatus::IntegrityFailure && store.raw(1).status == StoreStatus::Ok, "corrupt index disclosure");
    }
    require(rejected(ca, SplitOpenMode::Existing), "corrupt index restart");
    std::cout << "M6.10 paired-store and projection integrity refusal: PASS\n";
}
void two_volumes(const std::string& raw, const std::string& index) {
    const SplitStorageConfig c{inspect_storage_location(raw), inspect_storage_location(index)};
    require(c.raw.device != c.index.device && c.raw.mount_id != c.index.mount_id, "distinct mounted filesystems required");
    { SplitEventStore store(c, SplitOpenMode::CreateNew); require(append(store, wire("two-volumes")).durability == Durability::Durable && store.search({}).events.empty() && store.index(1).durability == Durability::Durable, "two-volume admission"); }
    { SplitEventStore store(c, SplitOpenMode::Existing); require(store.raw(1).value.has_value() && store.search({}).events.size() == 1, "two-volume restart"); }
    std::cout << "M6.10 explicitly approved distinct local filesystems and restart: PASS\n";
}
void head_recovery() {
    Fixture f; const auto c = f.config(); const auto head = f.raw() + "/head";
    {
        SplitEventStore store(c, SplitOpenMode::CreateNew);
        fs::copy_file(head, f.root + "/old-head");
        require(append(store, wire("recover")).status == StoreStatus::Ok, "head seed");
    }
    // Fixture reconstructs the one-record window between raw publication and head publication.
    fs::copy_file(f.root + "/old-head", head, fs::copy_options::overwrite_existing);
    {
        SplitEventStore store(c, SplitOpenMode::Existing);
        require(append(store, wire("recover")).status == StoreStatus::ExactRetry && store.pending(0, {}, 32).ids == std::vector<EventId>{1}, "head recovery");
    }
    fs::remove(f.raw() + "/event-1.raw");
    require(rejected(c, SplitOpenMode::Existing), "committed suffix loss across restart");
    std::cout << "M6.10 raw head recovery window and committed suffix deletion refusal: PASS\n";
}
void write_failure() {
    Fixture f; const auto c = f.config();
    { SplitEventStore store(c, SplitOpenMode::CreateNew); require(append(store, wire("committed")).status == StoreStatus::Ok, "seed"); }
    const auto pid = fork(); require(pid >= 0, "fork");
    if (pid == 0) {
        try {
            SplitEventStore store(c, SplitOpenMode::Existing);
            struct rlimit limit{}; require(getrlimit(RLIMIT_FSIZE, &limit) == 0, "getrlimit"); limit.rlim_cur = 0;
            require(signal(SIGXFSZ, SIG_IGN) != SIG_ERR && setrlimit(RLIMIT_FSIZE, &limit) == 0, "rlimit");
            const auto result = append(store, wire("failed")); require(result.id == 0 && result.durability == Durability::None, "false durable");
            require(store.index(1).durability == Durability::None, "false index durable");
            _exit(0);
        } catch (...) { _exit(1); }
    }
    int status{}; require(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child failure");
    SplitEventStore store(c, SplitOpenMode::Existing);
    require(store.pending(0, {}, 32).ids == std::vector<EventId>{1} && store.raw(2).status == StoreStatus::NotFound, "write rollback");
    require(store.index(1).status == StoreStatus::Ok && append(store, wire("retry")).id == 2, "retry after failure");
    std::cout << "M6.10 isolated actual file-write failures, no false durability and replay: PASS\n";
}
} // namespace
int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--mount-fixture") { mount_fixture(); return 0; }
        if (argc == 4 && std::string_view(argv[1]) == "--two-volumes") { two_volumes(argv[2], argv[3]); return 0; }
        require(argc == 1, "unknown test mode"); exercise(); head_recovery(); index_integrity(); write_failure(); return 0;
    }
    catch (const std::exception& e) { std::cerr << "M6.10: " << e.what() << '\n'; return 1; }
}

// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/storage/sqlite_event_store.hpp>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <array>
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cerrno>
#include <limits>
#include <stdexcept>
#include <utility>

namespace knetsentry::storage {
namespace {
constexpr auto ceiling = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
constexpr int application_id = 1263751988; // KnetSentry development store identifier.
constexpr char meta_sql[] = "CREATE TABLE meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL CHECK(revision>0),next_id INTEGER NOT NULL CHECK(next_id>0),schema_version TEXT NOT NULL CHECK(schema_version='1.4.0'),mapping_revision INTEGER NOT NULL CHECK(mapping_revision=1)) STRICT";
constexpr char events_sql[] = "CREATE TABLE events(id INTEGER PRIMARY KEY CHECK(id>0),binding TEXT NOT NULL CHECK(length(binding)=96),unit TEXT NOT NULL CHECK(length(unit) BETWEEN 1 AND 255),wire TEXT NOT NULL CHECK(length(wire) BETWEEN 1 AND 2048),mode INTEGER NOT NULL CHECK(mode BETWEEN 0 AND 2),received INTEGER NOT NULL CHECK(received>0),held INTEGER NOT NULL DEFAULT 0 CHECK(held IN(0,1)),endpoint TEXT NOT NULL CHECK(endpoint=substr(binding,1,32)),cursor TEXT NOT NULL CHECK(length(cursor) BETWEEN 1 AND 2048),time_ms INTEGER,class_uid INTEGER,status_id INTEGER,activity_id INTEGER,mapping INTEGER,CHECK((time_ms IS NULL AND class_uid IS NULL AND status_id IS NULL AND activity_id IS NULL AND mapping IS NULL) OR (time_ms IS NOT NULL AND time_ms>=0 AND class_uid IS NOT NULL AND class_uid IN(0,3002) AND status_id IS NOT NULL AND status_id BETWEEN 0 AND 2 AND activity_id IS NOT NULL AND activity_id BETWEEN 0 AND 2 AND mapping IS NOT NULL AND mapping BETWEEN 0 AND 4)),UNIQUE(endpoint,cursor)) STRICT";
constexpr char index_search[] = "CREATE INDEX event_search ON events(class_uid,status_id,time_ms,id) WHERE time_ms IS NOT NULL";
constexpr char index_binding[] = "CREATE INDEX event_binding ON events(binding,id) WHERE time_ms IS NOT NULL";
constexpr char index_retention[] = "CREATE INDEX event_retention ON events(received,id) WHERE held=0 AND time_ms IS NOT NULL";
constexpr char index_mode[] = "CREATE INDEX event_mode ON events(mode,id) WHERE time_ms IS NOT NULL";
constexpr char index_source[] = "CREATE INDEX event_source ON events(unit,mode,id) WHERE time_ms IS NOT NULL";
constexpr char index_time[] = "CREATE INDEX event_time ON events(time_ms,id) WHERE time_ms IS NOT NULL";
constexpr char integrity_sql[] = "CREATE TABLE evidence_integrity(id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,origin INTEGER NOT NULL CHECK(origin IN(0,1)),sha256 TEXT NOT NULL CHECK(length(sha256)=64)) STRICT";
constexpr char filename[] = "events-m64.sqlite3";
constexpr char journalname[] = "events-m64.sqlite3-journal";
struct DbError { StoreStatus status; };
[[noreturn]] void fail(int rc) {
    switch (rc & 0xff) {
    case SQLITE_BUSY: case SQLITE_LOCKED: case SQLITE_CANTOPEN: case SQLITE_READONLY:
        throw DbError{StoreStatus::Unavailable};
    case SQLITE_FULL: throw DbError{StoreStatus::Capacity};
    case SQLITE_CORRUPT: case SQLITE_NOTADB: case SQLITE_CONSTRAINT: case SQLITE_SCHEMA:
        throw DbError{StoreStatus::IntegrityFailure};
    default: throw DbError{StoreStatus::IoError};
    }
}
void checked(int rc) { if (rc != SQLITE_OK) { fail(rc); } }
void require(bool ok) { if (!ok) { throw DbError{StoreStatus::IntegrityFailure}; } }
void exec(sqlite3* db, const char* sql) { checked(sqlite3_exec(db, sql, nullptr, nullptr, nullptr)); }
class Statement final {
public:
    Statement(sqlite3* db, const char* sql) {
        const int rc = sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr);
        if (rc != SQLITE_OK) { sqlite3_finalize(stmt_); fail(rc); }
    }
    ~Statement() { sqlite3_finalize(stmt_); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    void number(int n, std::uint64_t v) { require(v <= ceiling); checked(sqlite3_bind_int64(stmt_, n, static_cast<sqlite3_int64>(v))); }
    void string(int n, std::string_view v) {
        require(v.size() <= 2048); checked(sqlite3_bind_text(stmt_, n, v.empty() ? "" : v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT));
    }
    bool row() {
        const auto rc = sqlite3_step(stmt_);
        if (rc == SQLITE_ROW) { return true; }
        if (rc == SQLITE_DONE) { return false; }
        fail(rc);
    }
    void done() { require(!row()); }
    bool null(int n) const { return sqlite3_column_type(stmt_, n) == SQLITE_NULL; }
    std::uint64_t number(int n) const {
        require(sqlite3_column_type(stmt_, n) == SQLITE_INTEGER);
        const auto v = sqlite3_column_int64(stmt_, n); require(v >= 0); return static_cast<std::uint64_t>(v);
    }
    std::string string(int n) const {
        require(sqlite3_column_type(stmt_, n) == SQLITE_TEXT);
        const auto* ptr = sqlite3_column_text(stmt_, n);
        const int size = sqlite3_column_bytes(stmt_, n);
        require(ptr != nullptr && size >= 0 && size <= 2048);
        return {reinterpret_cast<const char*>(ptr), static_cast<std::size_t>(size)};
    }
private:
    sqlite3_stmt* stmt_{};
};
std::uint64_t scalar(sqlite3* db, const char* sql) {
    Statement s(db, sql); require(s.row()); const auto v = s.number(0); s.done(); return v;
}
class Transaction final {
public:
    explicit Transaction(sqlite3* db) : db_(db) { exec(db_, "BEGIN IMMEDIATE"); }
    ~Transaction() { if (!committed_) { static_cast<void>(sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr)); } }
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    void commit() { exec(db_, "COMMIT"); committed_ = true; }
private:
    sqlite3* db_;
    bool committed_{};
};
bool valid_id(EventId id) { return id > 0 && id < ceiling; }
bool valid_received(std::uint64_t ms) { return ms > 0 && ms <= ceiling; }
std::uint64_t revision(sqlite3* db) { const auto v = scalar(db, "SELECT revision FROM meta WHERE singleton=1"); require(v > 0); return v; }
void advance(sqlite3* db) {
    if (revision(db) == ceiling) { throw DbError{StoreStatus::Exhausted}; }
    exec(db, "UPDATE meta SET revision=revision+1 WHERE singleton=1");
}
void verify_file(int dir, const char* name, bool absent_ok) {
    struct stat st{};
    if (fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        if (absent_ok && errno == ENOENT) { return; }
        throw DbError{StoreStatus::Unavailable};
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 07777) != 0600 || st.st_nlink != 1) {
        throw DbError{StoreStatus::Unavailable};
    }
}
int open_directory(const std::string& directory) {
    if (!agent::valid_journal_directory(directory)) {
        throw DbError{StoreStatus::Invalid};
    }
    struct open_how how{};
    how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
    how.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    const auto fd = static_cast<int>(syscall(SYS_openat2, AT_FDCWD, directory.c_str(), &how, sizeof(how)));
    if (fd < 0) { throw DbError{StoreStatus::Unavailable}; }
    return fd;
}
// Revision 1: domain + fixed-width big-endian integers and length-prefixed
// strings. Immutable evidence only; mutable hold/index state is separate.
std::string evidence_digest(const RawEvidence& raw, IntegrityOrigin origin) {
    std::string encoded{"KnetSentry:evidence:sha256:v1"};
    const auto number = [&encoded](std::uint64_t value) {
        for (unsigned shift = 64; shift != 0;) {
            shift -= 8;
            encoded.push_back(static_cast<char>((value >> shift) & 0xffU));
        }
    };
    const auto field = [&encoded, &number](std::string_view value) {
        number(value.size()); encoded.append(value);
    };
    number(origin == IntegrityOrigin::Admission ? 1U : 0U);
    number(raw.id); number(static_cast<std::uint64_t>(raw.mode)); number(raw.received_ms);
    field(raw.binding); field(raw.unit); field(raw.canonical_row);
    std::array<unsigned char, 32> digest{};
    std::size_t length{};
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, encoded.data(), encoded.size(), digest.data(), &length) != 1 || length != digest.size()) {
        throw DbError{StoreStatus::IoError};
    }
    constexpr std::string_view hex{"0123456789abcdef"};
    std::string result; result.reserve(64);
    for (const auto byte : digest) { result.push_back(hex[byte >> 4U]); result.push_back(hex[byte & 0xfU]); }
    return result;
}
void insert_integrity(sqlite3* db, const RawEvidence& raw, IntegrityOrigin origin) {
    const auto digest = evidence_digest(raw, origin);
    Statement s(db, "INSERT INTO evidence_integrity(id,origin,sha256) VALUES(?1,?2,?3)");
    s.number(1, raw.id); s.number(2, origin == IntegrityOrigin::Admission ? 1U : 0U);
    s.string(3, digest); s.done();
}
void verify_integrity(sqlite3* db, RawEvidence& raw) {
    Statement s(db, "SELECT origin,sha256 FROM evidence_integrity WHERE id=?1");
    s.number(1, raw.id); require(s.row());
    const auto numeric = s.number(0); require(numeric <= 1);
    const auto origin = numeric == 1 ? IntegrityOrigin::Admission : IntegrityOrigin::LegacyBaseline;
    auto digest = s.string(1); s.done();
    const auto expected = evidence_digest(raw, origin);
    require(digest.size() == expected.size() && CRYPTO_memcmp(digest.data(), expected.data(), expected.size()) == 0);
    raw.integrity = EvidenceIntegrity{std::move(digest), origin};
}
struct Stored {
    RawEvidence raw;
    agent::NormalizedEvent event;
    bool indexed{};
};
// The same canonical parser verifies original bytes and the pinned projection.
// No integer retrieved from disk is cast to an enum.
Stored decode(sqlite3* db, Statement& s, bool committed = true) {
    RawEvidence raw{s.number(0), s.string(1), s.string(2), s.string(3),
        agent::decode_journal_mode(static_cast<std::int64_t>(s.number(4))), s.number(5), s.number(6) == 1};
    require(valid_id(raw.id) && valid_received(raw.received_ms) && s.number(6) <= 1);
    auto normalized = agent::normalize_event(raw.canonical_row, raw.binding, raw.unit, raw.mode);
    require(normalized.has_value());
    // Schema pin 1 has no persisted severity column and emits only Unknown.
    require(normalized->severity_id == agent::OcsfSeverity::Unknown);
    require(s.string(7) == raw.binding.substr(0, 32) && s.string(8) == normalized->source.cursor);
    const bool indexed = !s.null(9);
    if (indexed) {
        require(s.number(9) == normalized->time_ms && s.number(10) == static_cast<std::uint64_t>(normalized->class_uid) &&
            s.number(11) == static_cast<std::uint64_t>(normalized->status_id) && s.number(12) == static_cast<std::uint64_t>(normalized->activity_id) &&
            s.number(13) == static_cast<std::uint64_t>(normalized->mapping));
    } else { require(s.null(10) && s.null(11) && s.null(12) && s.null(13)); }
    if (committed) { verify_integrity(db, raw); }
    return {std::move(raw), std::move(*normalized), indexed};
}
std::optional<Stored> get(sqlite3* db, EventId id) {
    if (!valid_id(id)) { return std::nullopt; }
    Statement s(db, "SELECT id,binding,unit,wire,mode,received,held,endpoint,cursor,time_ms,class_uid,status_id,activity_id,mapping FROM events WHERE id=?1");
    s.number(1, id); if (!s.row()) { return std::nullopt; }
    auto value = decode(db, s); s.done(); return value;
}
void validate_schema(sqlite3* db, std::uint64_t version) {
    Statement s(db, "SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name");
    if (version >= 2) {
        require(s.row() && s.string(0) == index_binding);
        if (version >= 4) { require(s.row() && s.string(0) == index_mode); }
        require(s.row() && s.string(0) == index_retention);
        require(s.row() && s.string(0) == index_search);
        if (version >= 4) {
            require(s.row() && s.string(0) == index_source);
            require(s.row() && s.string(0) == index_time);
        }
    }
    require(s.row() && s.string(0) == events_sql);
    if (version >= 3) { require(s.row() && s.string(0) == integrity_sql); }
    require(s.row() && s.string(0) == meta_sql); s.done();
}
void validate_evidence(sqlite3* db, bool committed) {
    { Statement pin(db, "SELECT schema_version,mapping_revision FROM meta WHERE singleton=1");
        require(pin.row() && pin.string(0) == agent::NormalizedEvent::schema_version &&
            pin.number(1) == agent::NormalizedEvent::mapping_revision); pin.done(); }
    require(scalar(db, "SELECT count(*) FROM meta") == 1 && revision(db) > 0);
    const auto next = scalar(db, "SELECT next_id FROM meta WHERE singleton=1");
    require(next > 0 && next > scalar(db, "SELECT coalesce(max(id),0) FROM events"));
    require(scalar(db, "SELECT count(*) FROM events") <= SqliteEventStore::max_records);
    Statement rows(db, "SELECT id,binding,unit,wire,mode,received,held,endpoint,cursor,time_ms,class_uid,status_id,activity_id,mapping FROM events ORDER BY id");
    while (rows.row()) { static_cast<void>(decode(db, rows, committed)); }
    if (committed) {
        require(scalar(db, "SELECT count(*) FROM evidence_integrity") == scalar(db, "SELECT count(*) FROM events"));
    }
}
void validate_contents(sqlite3* db, bool committed) {
    validate_evidence(db, committed);
    Statement check(db, "PRAGMA integrity_check(1)"); require(check.row() && check.string(0) == "ok"); check.done();
}
void verify_store(sqlite3* db) {
    require(scalar(db, "PRAGMA user_version") == 4 && scalar(db, "PRAGMA application_id") == static_cast<std::uint64_t>(application_id));
    validate_schema(db, 4);
    validate_evidence(db, true);
}
RetentionPreview preview(sqlite3* db, std::uint64_t before, std::size_t limit) {
    if (!valid_received(before) || limit == 0 || limit > EventStore::max_page) { return {}; }
    RetentionPlan plan{revision(db), before, limit, {}};
    Statement s(db, "SELECT id FROM events WHERE held=0 AND time_ms IS NOT NULL AND received<?1 ORDER BY id LIMIT ?2");
    s.number(1, before); s.number(2, limit);
    while (s.row()) { const auto id = s.number(0); const auto value = get(db, id); require(value && value->indexed && !value->raw.held && value->raw.received_ms < before); plan.ids.push_back(id); }
    return {StoreStatus::Ok, std::move(plan)};
}
} // namespace
struct SqliteEventStore::Impl {
    sqlite3* db{};
    int dir{-1};
    std::string directory_path;
    struct stat original_file{};
    void verify_sidecars() const {
        verify_file(dir, filename, false); verify_file(dir, journalname, true);
        for (const auto* name : {"events-m64.sqlite3-wal", "events-m64.sqlite3-shm"}) {
            struct stat side{};
            if (fstatat(dir, name, &side, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) { throw DbError{StoreStatus::Unavailable}; }
        }
    }
    sqlite3* checked_db() const {
        const int current = open_directory(directory_path);
        struct stat a{}, b{}, file{};
        const bool same = fstat(dir, &a) == 0 && fstat(current, &b) == 0 &&
            a.st_dev == b.st_dev && a.st_ino == b.st_ino && b.st_uid == geteuid() &&
            (b.st_mode & 07777) == 0700 && fstatat(current, filename, &file, AT_SYMLINK_NOFOLLOW) == 0 &&
            file.st_dev == original_file.st_dev && file.st_ino == original_file.st_ino;
        close(current);
        if (!same) { throw DbError{StoreStatus::Unavailable}; }
        verify_sidecars();
        if (sqlite3_get_autocommit(db) == 0) { throw DbError{StoreStatus::Unavailable}; }
        return db;
    }
    ~Impl() { if (db) { sqlite3_close(db); } if (dir >= 0) { close(dir); } }
    void open(const std::string& directory, LegacyIntegrityPolicy legacy, const StoragePolicy& policy, StorageOpenMode mode) {
        directory_path = directory;
        dir = open_directory(directory);
        struct stat st{};
        if (fstat(dir, &st) != 0 || st.st_uid != geteuid() || (st.st_mode & 07777) != 0700 || flock(dir, LOCK_EX | LOCK_NB) != 0) {
            throw DbError{StoreStatus::Unavailable};
        }
        struct statfs fs{};
        if (fstatfs(dir, &fs) != 0 || (fs.f_type != EXT4_SUPER_MAGIC && fs.f_type != XFS_SUPER_MAGIC &&
            fs.f_type != BTRFS_SUPER_MAGIC && fs.f_type != F2FS_SUPER_MAGIC && fs.f_type != OVERLAYFS_SUPER_MAGIC)) {
            throw DbError{StoreStatus::Unavailable};
        }
        // This dedicated directory is trusted by the caller. No symlinked or
        // shared files and no WAL/SHM mode from an incompatible application.
        verify_file(dir, filename, true); verify_file(dir, journalname, true);
        for (const auto* name : {"events-m64.sqlite3-wal", "events-m64.sqlite3-shm"}) {
            struct stat side{};
            if (fstatat(dir, name, &side, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) { throw DbError{StoreStatus::Unavailable}; }
        }
        if (mode == StorageOpenMode::Initialize) {
            const int file = openat(dir, filename, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
            if (file >= 0) { close(file); } else if (errno != EEXIST) { throw DbError{StoreStatus::Unavailable}; }
        }
        verify_file(dir, filename, false);
        require(fstatat(dir, filename, &original_file, AT_SYMLINK_NOFOLLOW) == 0);
        // SQLite NOFOLLOW rejects even /proc/self/fd links. Keep the checked
        // directory open and revalidate its identity before operations. The
        // caller must keep the approved path and ancestors stable.
        const auto path = directory + "/" + filename;
        require(sqlite3_libversion_number() >= 3037000);
        checked(sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOFOLLOW, nullptr));
        static_cast<void>(checked_db());
        checked(sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr));
        checked(sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr));
        checked(sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr));
        checked(sqlite3_busy_timeout(db, 100));
        sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 16384);
        sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 0);
        const auto version = scalar(db, "PRAGMA user_version");
        const auto app = scalar(db, "PRAGMA application_id");
        if (mode == StorageOpenMode::ExistingV4) { require(version == 4); }
        require((version == 0 && app == 0 && scalar(db, "SELECT count(*) FROM sqlite_schema") == 0) ||
            ((version == 1 || version == 2 || version == 3 || version == 4) && app == static_cast<std::uint64_t>(application_id)));
        if (version == 1 || version == 2) { require(legacy == LegacyIntegrityPolicy::EstablishBaseline); }
        if (version != 0) { validate_schema(db, version); }
        require(scalar(db, "PRAGMA page_size") == StoragePolicy::page_bytes &&
            scalar(db, "PRAGMA page_count") <= policy.database_page_limit);
        // Only validated bounded numeric policy input; PRAGMA does not accept bind parameters.
        const auto page_cap = "PRAGMA max_page_count=" + std::to_string(policy.database_page_limit);
        require(scalar(db, page_cap.c_str()) == policy.database_page_limit);
        { Statement journal_mode(db, "PRAGMA journal_mode=DELETE"); require(journal_mode.row() && journal_mode.string(0) == "delete"); journal_mode.done(); }
        exec(db, "PRAGMA synchronous=EXTRA; PRAGMA temp_store=MEMORY; PRAGMA secure_delete=ON; PRAGMA foreign_keys=ON");
        require(scalar(db, "PRAGMA foreign_keys") == 1);
        require(scalar(db, "PRAGMA synchronous") == 3 && scalar(db, "PRAGMA temp_store") == 2);
        Transaction tx(db);
        require(scalar(db, "PRAGMA user_version") == version && scalar(db, "PRAGMA application_id") == app);
        if (version != 0) { validate_schema(db, version); }
        else { require(scalar(db, "SELECT count(*) FROM sqlite_schema") == 0); }
        if (version == 0) {
            exec(db, meta_sql); exec(db, events_sql);
            exec(db, "INSERT INTO meta VALUES(1,1,1,'1.4.0',1); PRAGMA application_id=1263751988; PRAGMA user_version=1");
        }
        validate_contents(db, version >= 3);
        if (version < 2) {
            exec(db, index_search); exec(db, index_binding); exec(db, index_retention); exec(db, "PRAGMA user_version=2");
        }
        if (version < 3) {
            exec(db, integrity_sql);
            Statement rows(db, "SELECT id,binding,unit,wire,mode,received,held,endpoint,cursor,time_ms,class_uid,status_id,activity_id,mapping FROM events ORDER BY id");
            while (rows.row()) {
                insert_integrity(db, decode(db, rows, false).raw, IntegrityOrigin::LegacyBaseline);
            }
            exec(db, "PRAGMA user_version=3");
        }
        if (version < 4) {
            exec(db, index_mode); exec(db, index_source); exec(db, index_time);
            exec(db, "PRAGMA user_version=4");
        }
        validate_schema(db, 4);
        validate_contents(db, true);
        tx.commit();
        static_cast<void>(checked_db());
        if (fsync(dir) != 0) { throw DbError{StoreStatus::IoError}; }
    }
};
SqliteEventStore::SqliteEventStore(const std::string& directory, LegacyIntegrityPolicy legacy, StoragePolicy policy, StorageOpenMode mode)
    : EventStore(policy), impl_(std::make_unique<Impl>()) {
    try { impl_->open(directory, legacy, policy, mode); }
    catch (const DbError&) { throw std::runtime_error("SQLite development store activation rejected"); }
}
SqliteEventStore::~SqliteEventStore() = default;
ReadResult<StorageUsage> SqliteEventStore::usage() const try {
    auto* db = impl_->checked_db(); Transaction tx(db); verify_store(db);
    StorageUsage result;
    result.records = static_cast<std::size_t>(scalar(db, "SELECT count(*) FROM events"));
    result.wire_bytes = static_cast<std::size_t>(scalar(db, "SELECT coalesce(sum(length(CAST(wire AS BLOB))),0) FROM events"));
    result.held = static_cast<std::size_t>(scalar(db, "SELECT count(*) FROM events WHERE held=1"));
    result.pending = static_cast<std::size_t>(scalar(db, "SELECT count(*) FROM events WHERE time_ms IS NULL"));
    const auto pages = scalar(db, "PRAGMA page_count");
    const auto free = scalar(db, "PRAGMA freelist_count");
    require(pages <= policy().database_page_limit && free <= pages);
    result.disk = DiskUsage{static_cast<std::size_t>(pages), static_cast<std::size_t>(free),
        quota_warning(static_cast<std::size_t>(pages), policy().database_page_limit, policy().warning_percent)};
    result.record_warning = quota_warning(result.records, policy().record_limit, policy().warning_percent);
    result.wire_warning = quota_warning(result.wire_bytes, policy().wire_byte_limit, policy().warning_percent);
    tx.commit(); return {StoreStatus::Ok, result};
} catch (const DbError& e) { return {e.status, std::nullopt}; }
AppendResult SqliteEventStore::append(const RawInput& input) try {
    if (!valid_received(input.received_ms) || !agent::valid_delivery_binding(input.binding)) { return {}; }
    auto parsed = agent::parse_delivery_row(input.canonical_row, input.unit, input.mode); if (!parsed) { return {}; }
    auto* db = impl_->checked_db(); Transaction tx(db); verify_store(db);
    Statement lookup(db, "SELECT id FROM events WHERE endpoint=?1 AND cursor=?2");
    lookup.string(1, input.binding.substr(0, 32)); lookup.string(2, parsed->cursor);
    if (lookup.row()) {
        const auto id = lookup.number(0); lookup.done(); const auto existing = get(db, id); require(existing.has_value());
        const auto& raw = existing->raw;
        if (raw.binding != input.binding || raw.unit != input.unit || raw.mode != input.mode || raw.canonical_row != input.canonical_row) { return {StoreStatus::Conflict, 0, Durability::None}; }
        tx.commit(); return {StoreStatus::ExactRetry, id, Durability::Durable};
    }
    const auto used = scalar(db, "SELECT coalesce(sum(length(CAST(wire AS BLOB))),0) FROM events");
    if (scalar(db, "SELECT count(*) FROM events") >= policy().record_limit || used >= policy().wire_byte_limit ||
        input.canonical_row.size() > policy().wire_byte_limit - used) { return {StoreStatus::Capacity, 0, Durability::None}; }
    const auto id = scalar(db, "SELECT next_id FROM meta WHERE singleton=1");
    if (id == ceiling) { return {StoreStatus::Exhausted, 0, Durability::None}; }
    require(valid_id(id));
    advance(db);
    Statement s(db, "INSERT INTO events(id,binding,unit,wire,mode,received,endpoint,cursor) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)");
    s.number(1, id); s.string(2, input.binding); s.string(3, input.unit); s.string(4, input.canonical_row);
    s.number(5, static_cast<std::uint64_t>(input.mode)); s.number(6, input.received_ms); s.string(7, input.binding.substr(0, 32)); s.string(8, parsed->cursor); s.done();
    insert_integrity(db, RawEvidence{id, std::string(input.binding), std::string(input.unit), std::string(input.canonical_row), input.mode, input.received_ms, false}, IntegrityOrigin::Admission);
    exec(db, "UPDATE meta SET next_id=next_id+1 WHERE singleton=1"); tx.commit(); return {StoreStatus::Ok, id, Durability::Durable};
} catch (const DbError& e) { return {e.status, 0, Durability::None}; }
IndexResult SqliteEventStore::index(EventId id) try {
    auto* db = impl_->checked_db(); Transaction tx(db); verify_store(db); const auto value = get(db, id);
    if (!value) { return {StoreStatus::NotFound, Durability::None}; }
    if (value->indexed) { tx.commit(); return {StoreStatus::ExactRetry, Durability::Durable}; }
    const auto& event = value->event; advance(db);
    Statement s(db, "UPDATE events SET time_ms=?1,class_uid=?2,status_id=?3,activity_id=?4,mapping=?5 WHERE id=?6");
    s.number(1, event.time_ms); s.number(2, static_cast<std::uint64_t>(event.class_uid)); s.number(3, static_cast<std::uint64_t>(event.status_id));
    s.number(4, static_cast<std::uint64_t>(event.activity_id)); s.number(5, static_cast<std::uint64_t>(event.mapping)); s.number(6, id); s.done();
    tx.commit(); return {StoreStatus::Ok, Durability::Durable};
} catch (const DbError& e) { return {e.status, Durability::None}; }
ReadResult<RawEvidence> SqliteEventStore::raw(EventId id) const try {
    auto* db = impl_->checked_db(); Transaction tx(db); verify_store(db);
    auto value = get(db, id); tx.commit(); if (!value) { return {}; }
    return {StoreStatus::Ok, std::move(value->raw)};
} catch (const DbError& e) { return {e.status, std::nullopt}; }
ReadResult<agent::NormalizedEvent> SqliteEventStore::normalized(EventId id) const try {
    auto* db = impl_->checked_db(); Transaction tx(db); verify_store(db);
    auto value = get(db, id); tx.commit(); if (!value) { return {}; }
    if (!value->indexed) { return {StoreStatus::IndexPending, std::nullopt}; }
    return {StoreStatus::Ok, std::move(value->event)};
} catch (const DbError& e) { return {e.status, std::nullopt}; }
SearchPage SqliteEventStore::search(const SearchQuery& q) const try {
    SearchPage page;
    if (!valid_search_query(q)) { return page; }
    auto* db = impl_->checked_db(); Transaction tx(db); verify_store(db); page.revision = revision(db);
    if (q.revision && *q.revision != page.revision) { page.status = StoreStatus::Stale; return page; }
    page.status = StoreStatus::Ok;
    // Mapping revision 1 emits only Unknown severity. Verify the store even
    // for an impossible severity predicate; never manufacture a severity.
    if ((!q.descending && q.after >= ceiling) || q.from_ms > ceiling || (q.severity && *q.severity != agent::OcsfSeverity::Unknown)) {
        tx.commit(); return page;
    }
    // Compose only fixed clauses; user values are always bound parameters.
    // Avoid optional-filter OR expressions that prevent useful index lookups.
    std::string sql = "SELECT id,binding,unit,wire,mode,received,held,endpoint,cursor,time_ms,class_uid,status_id,activity_id,mapping FROM events WHERE time_ms IS NOT NULL AND time_ms BETWEEN ?2 AND ?3";
    sql += q.descending ? " AND id<?1" : " AND id>?1";
    if (q.class_uid) { sql += " AND class_uid=?4"; }
    if (q.status_id) { sql += " AND status_id=?5"; }
    if (!q.binding.empty()) { sql += " AND binding=?6"; }
    if (!q.source_unit.empty()) { sql += " AND unit=?8"; }
    if (q.source_mode) { sql += " AND mode=?9"; }
    if (q.category) { sql += " AND class_uid=?10"; }
    if (q.activity) { sql += " AND activity_id=?11"; }
    if (q.mapping) { sql += " AND mapping=?12"; }
    sql += q.descending ? " ORDER BY id DESC LIMIT ?7" : " ORDER BY id LIMIT ?7";
    Statement s(db, sql.c_str());
    s.number(1, q.descending && (q.after == 0 || q.after > ceiling) ? ceiling : q.after); s.number(2, q.from_ms); s.number(3, q.through_ms > ceiling ? ceiling : q.through_ms);
    if (q.class_uid) { s.number(4, static_cast<std::uint64_t>(*q.class_uid)); }
    if (q.status_id) { s.number(5, static_cast<std::uint64_t>(*q.status_id)); }
    if (!q.binding.empty()) { s.string(6, q.binding); }
    s.number(7, q.limit + 1);
    if (!q.source_unit.empty()) { s.string(8, q.source_unit); }
    if (q.source_mode) { s.number(9, static_cast<std::uint64_t>(*q.source_mode)); }
    if (q.category) { s.number(10, *q.category == agent::OcsfCategory::IdentityAndAccessManagement ? 3002U : 0U); }
    if (q.activity) { s.number(11, static_cast<std::uint64_t>(*q.activity)); }
    if (q.mapping) { s.number(12, static_cast<std::uint64_t>(*q.mapping)); }
    while (s.row()) {
        const auto v = decode(db, s); require(v.indexed && matches_search_query(q, v.raw, v.event));
        if (page.events.size() == q.limit) { page.more = true; break; }
        page.events.push_back(summarize_event(v.raw, v.event));
    }
    tx.commit(); return page;
} catch (const DbError& e) { return {e.status, 0, {}, false}; }
PendingPage SqliteEventStore::pending(EventId after, std::optional<std::uint64_t> rev, std::size_t limit) const try {
    PendingPage page; if (limit == 0 || limit > max_page || (after != 0 && !rev)) { return page; }
    auto* db = impl_->checked_db(); Transaction tx(db); verify_store(db); page.revision = revision(db);
    if (rev && *rev != page.revision) { page.status = StoreStatus::Stale; return page; }
    page.status = StoreStatus::Ok;
    if (after >= ceiling) { tx.commit(); return page; }
    Statement s(db, "SELECT id FROM events WHERE time_ms IS NULL AND id>?1 ORDER BY id LIMIT ?2"); s.number(1, after); s.number(2, limit+1);
    while (s.row()) {
        const auto id = s.number(0); const auto v = get(db, id); require(v && !v->indexed);
        if (page.ids.size() == limit) { page.more = true; break; }
        page.ids.push_back(id);
    }
    tx.commit(); return page;
} catch (const DbError& e) { return {e.status, 0, {}, false}; }
StoreStatus SqliteEventStore::set_hold(EventId id, bool held) try {
    auto* db = impl_->checked_db(); Transaction tx(db); verify_store(db); const auto value = get(db, id);
    if (!value) { return StoreStatus::NotFound; }
    if (value->raw.held == held) { tx.commit(); return StoreStatus::ExactRetry; }
    advance(db); Statement s(db, "UPDATE events SET held=?1 WHERE id=?2"); s.number(1, held ? 1U : 0U); s.number(2, id); s.done(); tx.commit(); return StoreStatus::Ok;
} catch (const DbError& e) { return e.status; }
RetentionPreview SqliteEventStore::preview_retention(std::uint64_t before, std::size_t limit) const try {
    auto* db = impl_->checked_db(); Transaction tx(db); verify_store(db); auto result = preview(db, before, limit); tx.commit(); return result;
} catch (const DbError& e) { return {e.status, std::nullopt}; }
RetentionResult SqliteEventStore::apply_retention(const RetentionPlan& plan) try {
    if (plan.ids.size() > max_page) { return {}; }
    auto* db = impl_->checked_db(); Transaction tx(db); verify_store(db);
    if (plan.revision != revision(db)) { return {StoreStatus::Stale, 0}; }
    const auto expected = preview(db, plan.before_received_ms, plan.limit);
    if (!expected.plan || expected.plan->ids != plan.ids) { return {}; }
    if (!plan.ids.empty()) {
        advance(db);
        for (const auto id : plan.ids) {
            Statement s(db, "DELETE FROM events WHERE id=?1 AND held=0 AND time_ms IS NOT NULL"); s.number(1, id); s.done(); require(sqlite3_changes(db) == 1);
        }
    }
    tx.commit(); return {StoreStatus::Ok, plan.ids.size()};
} catch (const DbError& e) { return {e.status, 0}; }
} // namespace knetsentry::storage

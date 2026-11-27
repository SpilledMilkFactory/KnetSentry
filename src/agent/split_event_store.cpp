// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/storage/split_event_store.hpp>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <linux/openat2.h>
#include <linux/magic.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/file.h>
#include <sys/random.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <algorithm>
#include <charconv>
#include <cerrno>
#include <memory>
#include <stdexcept>
#include <utility>

namespace knetsentry::storage {
namespace {
struct Failure { StoreStatus status; };
void require(bool ok, StoreStatus status = StoreStatus::IntegrityFailure) {
    if (!ok) { throw Failure{status}; }
}
class Fd final {
public:
    explicit Fd(int fd) : fd_(fd) { require(fd_ >= 0, StoreStatus::Unavailable); }
    ~Fd() { close(fd_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    [[nodiscard]] int get() const { return fd_; }
private:
    int fd_;
};
int directory_fd(const std::string& path) {
    require(agent::valid_journal_directory(path), StoreStatus::Invalid);
    struct open_how how{};
    how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
    how.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    return static_cast<int>(syscall(SYS_openat2, AT_FDCWD, path.c_str(), &how, sizeof(how)));
}
std::string boot_identity() {
    const Fd fd(open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    std::array<char, 37> bytes{};
    require(read(fd.get(), bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()) && bytes.back() == '\n', StoreStatus::Unavailable);
    return {bytes.data(), bytes.size() - 1};
}
LocationApproval identify(int fd, const std::string& path, bool overlay) {
    struct stat st{};
    struct statx sx{};
    struct statfs fs{};
    require(fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
        (st.st_mode & 07777) == 0700 && fstatfs(fd, &fs) == 0 &&
        statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE, &sx) == 0 &&
        (sx.stx_mask & STATX_MNT_ID_UNIQUE) != 0 && sx.stx_mnt_id != 0, StoreStatus::Unavailable);
    require(fs.f_type == EXT4_SUPER_MAGIC || fs.f_type == XFS_SUPER_MAGIC ||
        fs.f_type == BTRFS_SUPER_MAGIC || fs.f_type == F2FS_SUPER_MAGIC ||
        (overlay && fs.f_type == OVERLAYFS_SUPER_MAGIC), StoreStatus::Unavailable);
    return {path, boot_identity(), sx.stx_mnt_id, static_cast<std::uint64_t>(st.st_dev),
        static_cast<std::uint64_t>(st.st_ino), static_cast<std::uint64_t>(fs.f_type),
        {fs.f_fsid.__val[0], fs.f_fsid.__val[1]}, overlay};
}
class Location final {
public:
    explicit Location(const LocationApproval& approval) : approval_(approval), fd_(directory_fd(approval.path)) {
        verify(); require(flock(fd(), LOCK_EX | LOCK_NB) == 0, StoreStatus::Unavailable);
    }
    [[nodiscard]] int fd() const { return fd_.get(); }
    void verify_file_mount(int file) const {
        struct statx sx{};
        require(statx(file, "", AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE, &sx) == 0 &&
            (sx.stx_mask & STATX_MNT_ID_UNIQUE) != 0 && sx.stx_mnt_id == approval_.mount_id, StoreStatus::Unavailable);
    }
    void verify() const {
        const Fd current(directory_fd(approval_.path));
        require(identify(fd(), approval_.path, approval_.development_overlay) == approval_ &&
            identify(current.get(), approval_.path, approval_.development_overlay) == approval_, StoreStatus::Unavailable);
    }
    void space(std::uint64_t reserve, std::size_t bytes) const {
        verify(); struct statvfs fs{};
        require(fstatvfs(fd(), &fs) == 0 && fs.f_frsize > 0 && (fs.f_flag & ST_RDONLY) == 0, StoreStatus::Unavailable);
        const auto required = reserve + bytes;
        const auto blocks = required / fs.f_frsize + (required % fs.f_frsize != 0 ? 1U : 0U);
        require(fs.f_bavail >= blocks && fs.f_favail > 0, StoreStatus::Capacity);
    }
private:
    LocationApproval approval_;
    Fd fd_;
};
std::vector<std::string> names(const Location& loc) {
    loc.verify();
    const int fd = openat(loc.fd(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fd >= 0, StoreStatus::Unavailable);
    auto* stream = fdopendir(fd);
    if (!stream) { close(fd); throw Failure{StoreStatus::IoError}; }
    const auto close_dir = [](DIR* value) { closedir(value); };
    const std::unique_ptr<DIR, decltype(close_dir)> dir(stream, close_dir);
    std::vector<std::string> result;
    while (true) {
        errno = 0; const auto* entry = readdir(dir.get());
        if (!entry) { require(errno == 0, StoreStatus::IoError); break; }
        const std::string_view name(entry->d_name);
        if (name == "." || name == "..") { continue; }
        require(result.size() < StoragePolicy::record_ceiling + 2);
        result.emplace_back(name);
    }
    return result;
}
int open_regular(const Location& loc, const char* name) {
    loc.verify();
    struct stat prior{};
    require(fstatat(loc.fd(), name, &prior, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(prior.st_mode) &&
        prior.st_uid == geteuid() && (prior.st_mode & 07777) == 0600 && prior.st_nlink == 1);
    struct open_how how{};
    how.flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
    how.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    return static_cast<int>(syscall(SYS_openat2, loc.fd(), name, &how, sizeof(how)));
}
std::string read_file(const Location& loc, const char* name, std::size_t cap) {
    const Fd fd(open_regular(loc, name));
    loc.verify_file_mount(fd.get());
    struct stat st{};
    require(fstat(fd.get(), &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        (st.st_mode & 07777) == 0600 && st.st_nlink == 1 && st.st_size > 0 &&
        static_cast<std::uint64_t>(st.st_size) <= cap);
    std::string data(static_cast<std::size_t>(st.st_size), '\0');
    std::size_t offset{};
    while (offset < data.size()) {
        const auto n = read(fd.get(), data.data() + offset, data.size() - offset);
        if (n < 0 && errno == EINTR) { continue; }
        require(n > 0, StoreStatus::IoError); offset += static_cast<std::size_t>(n);
    }
    char extra{}; require(read(fd.get(), &extra, 1) == 0); loc.verify(); return data;
}
// Anonymous temporary inode: no abandoned partially written raw filename.
// Only the approved directory descriptor is used for publication.
void publish(const Location& loc, const char* name, std::string_view bytes,
    std::uint64_t reserve, bool replace = false) {
    loc.space(reserve, bytes.size());
    const Fd fd(openat(loc.fd(), ".", O_WRONLY | O_TMPFILE | O_CLOEXEC, 0600));
    loc.verify_file_mount(fd.get());
    require(fchmod(fd.get(), 0600) == 0, StoreStatus::IoError);
    std::size_t offset{};
    while (offset < bytes.size()) {
        const auto n = write(fd.get(), bytes.data() + offset, bytes.size() - offset);
        if (n < 0 && errno == EINTR) { continue; }
        require(n > 0, errno == ENOSPC || errno == EDQUOT ? StoreStatus::Capacity : StoreStatus::IoError);
        offset += static_cast<std::size_t>(n);
    }
    require(fsync(fd.get()) == 0, StoreStatus::IoError); loc.verify();
    const auto source = "/proc/self/fd/" + std::to_string(fd.get());
    const auto pending = std::string(name) + ".pending";
    const char* target = replace ? pending.c_str() : name;
    require(linkat(AT_FDCWD, source.c_str(), loc.fd(), target, AT_SYMLINK_FOLLOW) == 0, StoreStatus::IoError);
    if (replace && renameat(loc.fd(), target, loc.fd(), name) != 0) {
        // Leave the unexpected pending file for explicit recovery, not deletion.
        throw Failure{StoreStatus::IoError};
    }
    require(fsync(loc.fd()) == 0, StoreStatus::IoError); loc.verify();
}
std::string hex(const unsigned char* data, std::size_t size) {
    constexpr std::string_view digits{"0123456789abcdef"}; std::string result;
    for (std::size_t i = 0; i < size; ++i) {
        result.push_back(digits[data[i] >> 4U]); result.push_back(digits[data[i] & 15U]);
    }
    return result;
}
std::string digest(std::string_view data) {
    std::array<unsigned char, 32> out{}; std::size_t size{};
    require(EVP_Q_digest(nullptr, "SHA256", nullptr, data.data(), data.size(), out.data(), &size) == 1 &&
        size == out.size(), StoreStatus::IoError);
    return hex(out.data(), out.size());
}
std::string token() {
    std::array<unsigned char, 16> bytes{};
    require(getrandom(bytes.data(), bytes.size(), 0) == static_cast<ssize_t>(bytes.size()), StoreStatus::IoError);
    return hex(bytes.data(), bytes.size());
}
bool is_hex(std::string_view value, std::size_t size) {
    return value.size() == size && value.find_first_not_of("0123456789abcdef") == value.npos;
}
std::uint64_t number(std::string_view value) {
    std::uint64_t n{}; const auto result = std::from_chars(value.data(), value.data() + value.size(), n);
    require(result.ec == std::errc{} && result.ptr == value.data() + value.size() && std::to_string(n) == value);
    return n;
}
std::string take(std::string_view& view) {
    const auto pos = view.find('\n'); require(pos != view.npos);
    std::string result(view.substr(0, pos)); view.remove_prefix(pos + 1); return result;
}
std::string raw_name(EventId id) { return "event-" + std::to_string(id) + ".raw"; }
std::string encode(const RawInput& input, EventId id, const std::string& pair) {
    const auto body = "KNETSENTRY-RAW-M610-V1\n" + pair + '\n' + std::to_string(id) + '\n' +
        std::to_string(input.received_ms) + '\n' + std::to_string(static_cast<unsigned>(input.mode)) + '\n' +
        std::string(input.binding) + '\n' + std::string(input.unit) + '\n' + std::string(input.canonical_row);
    return digest(body) + '\n' + body;
}
struct RawSet {
    explicit RawSet(const StoragePolicy& policy) : reference(policy) {}
    MemoryEventStore reference;
    std::vector<RawEvidence> records;
    std::size_t committed{};
};
std::string head_value(const std::string& pair, const std::vector<RawEvidence>& records, std::size_t count) {
    auto input = "KNETSENTRY-RAW-HEAD-V1\n" + pair + '\n';
    for (std::size_t i = 0; i < count; ++i) { input += records.at(i).integrity.value().sha256; }
    return std::to_string(count) + '\n' + digest(input);
}
std::unique_ptr<RawSet> load_raw(const Location& loc, const StoragePolicy& policy, const std::string& pair) {
    const auto files = names(loc);
    require(std::ranges::find(files, "store.id") != files.end() && std::ranges::find(files, "head") != files.end() && files.size() >= 2 && files.size() <= policy.record_limit + 2);
    require(read_file(loc, "store.id", 32) == pair);
    auto result = std::make_unique<RawSet>(policy);
    for (EventId id = 1; id <= files.size() - 2; ++id) {
        const auto name = raw_name(id);
        require(std::ranges::find(files, name) != files.end());
        const auto bytes = read_file(loc, name.c_str(), 4096);
        std::string_view view(bytes); const auto sha = take(view);
        require(is_hex(sha, 64) && digest(view) == sha && take(view) == "KNETSENTRY-RAW-M610-V1" && take(view) == pair);
        require(number(take(view)) == id); const auto received = number(take(view));
        const auto mode_number = number(take(view)); require(mode_number <= 2);
        const auto mode = mode_number == 0 ? agent::JournalMode::Metadata :
            mode_number == 1 ? agent::JournalMode::Authentication : agent::JournalMode::Audit;
        const auto binding = take(view); const auto unit = take(view);
        const auto admission = result->reference.append({binding, unit, view, mode, received});
        require(admission.status == StoreStatus::Ok && admission.id == id);
        auto raw = result->reference.raw(id).value.value();
        raw.integrity = EvidenceIntegrity{sha, IntegrityOrigin::Admission};
        result->records.push_back(std::move(raw));
    }
    const auto head = read_file(loc, "head", 80);
    std::string_view head_view(head); const auto count = number(take(head_view));
    require(count <= result->records.size() && result->records.size() - count <= 1 &&
        head == head_value(pair, result->records, static_cast<std::size_t>(count)));
    result->committed = static_cast<std::size_t>(count);
    loc.verify(); return result;
}
constexpr char schema[] = "CREATE TABLE projection(id INTEGER PRIMARY KEY,sha TEXT NOT NULL,unit TEXT NOT NULL,mode INTEGER NOT NULL,received INTEGER NOT NULL,time_ms INTEGER NOT NULL,class_uid INTEGER NOT NULL,status_id INTEGER NOT NULL,activity_id INTEGER NOT NULL,mapping INTEGER NOT NULL) STRICT";
constexpr char meta[] = "CREATE TABLE pairing(id TEXT PRIMARY KEY) STRICT";
constexpr char index_sql[] = "CREATE INDEX projection_search ON projection(unit,mode,status_id,time_ms,id)";
void sqlcheck(int rc) { require(rc == SQLITE_OK, rc == SQLITE_FULL ? StoreStatus::Capacity : StoreStatus::IntegrityFailure); }
class Db final {
public:
    Db() {
        const auto rc = sqlite3_open_v2(":memory:", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_PRIVATECACHE, nullptr);
        if (rc != SQLITE_OK) { sqlite3_close(db); throw Failure{StoreStatus::IoError}; }
        try {
            sqlcheck(sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr));
            sqlcheck(sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr));
            sqlcheck(sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr));
            sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 0);
            sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 16384);
            sqlcheck(sqlite3_exec(db, "PRAGMA temp_store=MEMORY", nullptr, nullptr, nullptr));
        } catch (...) { sqlite3_close(db); throw; }
    }
    ~Db() { sqlite3_close(db); }
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;
    void exec(const char* text) const { sqlcheck(sqlite3_exec(db, text, nullptr, nullptr, nullptr)); }
    sqlite3* db{};
};
class Statement final {
public:
    Statement(const Db& db, const char* sql) {
        const auto rc = sqlite3_prepare_v2(db.db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) { sqlite3_finalize(stmt); sqlcheck(rc); }
    }
    ~Statement() { sqlite3_finalize(stmt); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    void text(int i, std::string_view s) const { sqlcheck(sqlite3_bind_text(stmt, i, s.data(), static_cast<int>(s.size()), SQLITE_TRANSIENT)); }
    void num(int i, std::uint64_t n) const { sqlcheck(sqlite3_bind_int64(stmt, i, static_cast<sqlite3_int64>(n))); }
    bool row() const { const auto rc = sqlite3_step(stmt); if (rc == SQLITE_ROW) { return true; } if (rc != SQLITE_DONE) { sqlcheck(rc); } return false; }
    std::string text(int i) const {
        require(sqlite3_column_type(stmt, i) == SQLITE_TEXT); const auto* p = sqlite3_column_text(stmt, i);
        const auto len = sqlite3_column_bytes(stmt, i); require(p && len >= 0 && len <= 2048);
        return {reinterpret_cast<const char*>(p), static_cast<std::size_t>(len)};
    }
    std::uint64_t num(int i) const {
        require(sqlite3_column_type(stmt, i) == SQLITE_INTEGER && sqlite3_column_int64(stmt, i) >= 0);
        return static_cast<std::uint64_t>(sqlite3_column_int64(stmt, i));
    }
private:
    sqlite3_stmt* stmt{};
};
std::array<std::uint64_t, 7> projection(const RawEvidence& raw) {
    const auto event = agent::normalize_event(raw.canonical_row, raw.binding, raw.unit, raw.mode);
    require(event.has_value());
    return {static_cast<std::uint64_t>(raw.mode), raw.received_ms, event->time_ms,
        static_cast<std::uint64_t>(event->class_uid), static_cast<std::uint64_t>(event->status_id),
        static_cast<std::uint64_t>(event->activity_id), static_cast<std::uint64_t>(event->mapping)};
}
constexpr char index_name[] = "projection.sqlite3";
std::size_t index_cap(const StoragePolicy& policy) { return policy.database_page_limit * StoragePolicy::page_bytes; }
void save_index(const Location& loc, const StoragePolicy& policy, std::uint64_t reserve,
    const std::string& pair, const RawSet& raw, const std::vector<EventId>& ids, bool replace) {
    Db db; db.exec("PRAGMA page_size=4096; PRAGMA temp_store=MEMORY");
    const auto cap = "PRAGMA max_page_count=" + std::to_string(policy.database_page_limit);
    db.exec(cap.c_str()); db.exec("BEGIN"); db.exec(schema); db.exec(meta); db.exec(index_sql);
    { Statement s(db, "INSERT INTO pairing VALUES(?1)"); s.text(1, pair); require(!s.row()); }
    for (const auto id : ids) {
        const auto& record = raw.records.at(static_cast<std::size_t>(id - 1));
        Statement s(db, "INSERT INTO projection VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)");
        s.num(1, id); s.text(2, record.integrity.value().sha256); s.text(3, record.unit);
        const auto values = projection(record);
        for (std::size_t i = 0; i < values.size(); ++i) { s.num(static_cast<int>(i) + 4, values[i]); }
        require(!s.row());
    }
    db.exec("COMMIT"); sqlite3_int64 length{};
    const std::unique_ptr<unsigned char, decltype(&sqlite3_free)> bytes(sqlite3_serialize(db.db, "main", &length, 0), sqlite3_free);
    require(bytes && length > 0 && static_cast<std::uint64_t>(length) <= index_cap(policy), StoreStatus::Capacity);
    publish(loc, index_name, {reinterpret_cast<const char*>(bytes.get()), static_cast<std::size_t>(length)}, reserve, replace);
}
std::vector<EventId> load_index(const Location& loc, const StoragePolicy& policy, const std::string& pair, RawSet& raw) {
    const auto files = names(loc); require(files == std::vector<std::string>{index_name});
    auto bytes = read_file(loc, index_name, index_cap(policy));
    Db db; // Buffer outlives db. No SQLite filesystem pathname or sidecar access.
    sqlcheck(sqlite3_deserialize(db.db, "main", reinterpret_cast<unsigned char*>(bytes.data()),
        static_cast<sqlite3_int64>(bytes.size()), static_cast<sqlite3_int64>(bytes.size()), SQLITE_DESERIALIZE_READONLY));
    { Statement s(db, "SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name");
      require(s.row() && s.text(0) == meta && s.row() && s.text(0) == schema && s.row() && s.text(0) == index_sql && !s.row()); }
    { Statement s(db, "PRAGMA integrity_check(1)"); require(s.row() && s.text(0) == "ok" && !s.row()); }
    { Statement s(db, "SELECT id FROM pairing"); require(s.row() && s.text(0) == pair && !s.row()); }
    std::vector<EventId> ids;
    Statement s(db, "SELECT id,sha,unit,mode,received,time_ms,class_uid,status_id,activity_id,mapping FROM projection ORDER BY id");
    while (s.row()) {
        const auto id = s.num(0); require(id > 0 && id <= raw.committed && (ids.empty() || ids.back() < id));
        const auto& record = raw.records.at(static_cast<std::size_t>(id - 1));
        require(s.text(1) == record.integrity.value().sha256 && s.text(2) == record.unit);
        const auto values = projection(record);
        for (std::size_t i = 0; i < values.size(); ++i) { require(s.num(static_cast<int>(i) + 3) == values[i]); }
        require(raw.reference.index(id).status == StoreStatus::Ok); ids.push_back(id);
    }
    loc.verify(); return ids;
}
} // namespace
LocationApproval inspect_storage_location(const std::string& path, bool overlay) try {
    const Fd fd(directory_fd(path)); return identify(fd.get(), path, overlay);
} catch (const Failure&) { throw std::runtime_error("storage location rejected"); }
struct SplitEventStore::Impl {
    SplitStorageConfig config;
    Location raw_location, index_location;
    std::string pair;
    mutable std::vector<std::string> observed;
    mutable std::vector<EventId> observed_index;
    explicit Impl(const SplitStorageConfig& c, SplitOpenMode mode) : config(c), raw_location(c.raw), index_location(c.index) {
        require(valid_storage_policy(c.policy) && c.policy.retention_ms == 0 && c.reserve_bytes <= (std::uint64_t{1} << 50U) &&
            !(c.raw.device == c.index.device && c.raw.inode == c.index.inode) &&
            !c.raw.path.starts_with(c.index.path + '/') && !c.index.path.starts_with(c.raw.path + '/'), StoreStatus::Invalid);
        if (mode == SplitOpenMode::CreateNew) {
            require(names(raw_location).empty() && names(index_location).empty(), StoreStatus::Invalid);
            raw_location.space(c.reserve_bytes, 32); index_location.space(c.reserve_bytes, index_cap(c.policy));
            pair = token(); publish(raw_location, "store.id", pair, c.reserve_bytes);
            const RawSet raw(c.policy); publish(raw_location, "head", head_value(pair, raw.records, 0), c.reserve_bytes);
            save_index(index_location, c.policy, c.reserve_bytes, pair, raw, {}, false);
        } else {
            require(mode == SplitOpenMode::Existing, StoreStatus::Invalid);
            pair = read_file(raw_location, "store.id", 32); require(is_hex(pair, 32));
        }
        auto raw = load_raw(raw_location, config.policy, pair);
        static_cast<void>(read_index(*raw));
        static_cast<void>(load(true));
    }
    [[nodiscard]] std::vector<EventId> read_index(RawSet& raw) const {
        auto ids = load_index(index_location, config.policy, pair, raw);
        require(std::includes(ids.begin(), ids.end(), observed_index.begin(), observed_index.end()));
        observed_index = ids; return ids;
    }
    [[nodiscard]] std::unique_ptr<RawSet> load(bool recover = false) const {
        auto raw = load_raw(raw_location, config.policy, pair);
        require(raw->records.size() >= observed.size());
        std::vector<std::string> digests;
        for (const auto& record : raw->records) { digests.push_back(record.integrity.value().sha256); }
        require(std::equal(observed.begin(), observed.end(), digests.begin()));
        if (raw->committed != raw->records.size()) {
            require(recover, StoreStatus::Unavailable);
            const auto name = raw_name(raw->records.back().id);
            const Fd fd(open_regular(raw_location, name.c_str()));
            raw_location.verify_file_mount(fd.get());
            require(fsync(fd.get()) == 0 && fsync(raw_location.fd()) == 0, StoreStatus::IoError);
            publish(raw_location, "head", head_value(pair, raw->records, raw->records.size()), config.reserve_bytes, true);
            raw->committed = raw->records.size();
        }
        observed = std::move(digests); return raw;
    }
};
SplitEventStore::SplitEventStore(const SplitStorageConfig& config, SplitOpenMode mode) try
    : impl_(std::make_unique<Impl>(config, mode)) {} catch (const Failure&) { throw std::runtime_error("split storage activation rejected"); }
SplitEventStore::~SplitEventStore() = default;
AppendResult SplitEventStore::append(const RawInput& input) try {
    auto raw = impl_->load(true); const auto result = raw->reference.append(input);
    if (result.status == StoreStatus::ExactRetry) {
        // Retry must not claim durability if a previous directory sync failed.
        const auto name = raw_name(result.id); const Fd fd(open_regular(impl_->raw_location, name.c_str()));
        impl_->raw_location.verify_file_mount(fd.get());
        require(fsync(fd.get()) == 0 && fsync(impl_->raw_location.fd()) == 0, StoreStatus::IoError);
        impl_->raw_location.verify(); return {result.status, result.id, Durability::Durable};
    }
    if (result.status != StoreStatus::Ok) { return result; }
    const auto bytes = encode(input, result.id, impl_->pair); const auto name = raw_name(result.id);
    publish(impl_->raw_location, name.c_str(), bytes, impl_->config.reserve_bytes);
    auto record = raw->reference.raw(result.id).value.value();
    record.integrity = EvidenceIntegrity{bytes.substr(0, 64), IntegrityOrigin::Admission};
    raw->records.push_back(std::move(record));
    publish(impl_->raw_location, "head", head_value(impl_->pair, raw->records, raw->records.size()), impl_->config.reserve_bytes, true);
    impl_->observed.push_back(bytes.substr(0, 64));
    return {StoreStatus::Ok, result.id, Durability::Durable};
} catch (const Failure& e) { return {e.status, 0, Durability::None}; }
IndexResult SplitEventStore::index(EventId id) try {
    auto raw = impl_->load(); auto ids = impl_->read_index(*raw);
    if (id == 0 || id > raw->records.size()) { return {StoreStatus::NotFound, Durability::None}; }
    const auto raw_file = raw_name(id);
    const Fd raw_fd(open_regular(impl_->raw_location, raw_file.c_str()));
    impl_->raw_location.verify_file_mount(raw_fd.get());
    require(fsync(raw_fd.get()) == 0 && fsync(impl_->raw_location.fd()) == 0, StoreStatus::IoError);
    impl_->raw_location.verify();
    if (std::ranges::find(ids, id) != ids.end()) {
        const Fd fd(open_regular(impl_->index_location, index_name));
        impl_->index_location.verify_file_mount(fd.get());
        require(fsync(fd.get()) == 0 && fsync(impl_->index_location.fd()) == 0, StoreStatus::IoError);
        impl_->index_location.verify(); return {StoreStatus::ExactRetry, Durability::Durable};
    }
    ids.push_back(id); std::ranges::sort(ids);
    save_index(impl_->index_location, impl_->config.policy, impl_->config.reserve_bytes, impl_->pair, *raw, ids, true);
    impl_->raw_location.verify();
    impl_->observed_index = std::move(ids);
    return {StoreStatus::Ok, Durability::Durable};
} catch (const Failure& e) { return {e.status, Durability::None}; }
ReadResult<RawEvidence> SplitEventStore::raw(EventId id) const try {
    const auto raw = impl_->load(); if (id == 0 || id > raw->records.size()) { return {}; }
    return {StoreStatus::Ok, raw->records.at(static_cast<std::size_t>(id - 1))};
} catch (const Failure& e) { return {e.status, std::nullopt}; }
SearchPage SplitEventStore::search(const SearchQuery& query) const try {
    auto raw = impl_->load(); static_cast<void>(impl_->read_index(*raw));
    impl_->raw_location.verify(); return raw->reference.search(query);
} catch (const Failure& e) { SearchPage result; result.status = e.status; return result; }
PendingPage SplitEventStore::pending(EventId after, std::optional<std::uint64_t> revision, std::size_t limit) const try {
    auto raw = impl_->load(); static_cast<void>(impl_->read_index(*raw));
    impl_->raw_location.verify(); return raw->reference.pending(after, revision, limit);
} catch (const Failure& e) { PendingPage result; result.status = e.status; return result; }
} // namespace knetsentry::storage

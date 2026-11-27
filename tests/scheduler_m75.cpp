// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/scheduler.hpp>
#include <knetsentry/storage/sqlite_event_store.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <array>
#include <stdexcept>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <csignal>
#include <unistd.h>

namespace {
using namespace knetsentry::detection;
using namespace knetsentry::storage;
using namespace knetsentry::agent;
using D = ScheduleStatus;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
class Fixture final {
public:
    Fixture() {
        char name[] = "/var/tmp/ks-m75-XXXXXX";
        const auto* p = ::mkdtemp(name); require(p != nullptr, "fixture directory"); path = p;
    }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(path, error); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    std::string path;
    std::string file() const { return path + "/schedule-m75.v1"; }
    std::string pending() const { return path + "/schedule-m75.pending"; }
};
SchedulePolicy policy() {
    SchedulePolicy p;
    p.store_identity = std::string(64, 'e');
    p.binding = std::string(32, 'a') + std::string(64, 'b');
    p.interval_ms = 10; p.window_ms = 100; p.suppression_ms = 50; p.threshold = 2;
    p.rule.schema_version = ValidatedRuleSet::schema_version;
    p.rule.ocsf_version = NormalizedEvent::schema_version;
    p.rule.mapping_revision = NormalizedEvent::mapping_revision;
    p.rule.predicate = {"ssh-failure", 1, OcsfActivity::Logon, OcsfStatus::Failure, "ssh.service"};
    p.rule.title = "Authentication failures";
    p.rule.description = "Synthetic rule; reported observation only.";
    p.rule.severity = RuleSeverity::Medium;
    p.rule.source_mode = JournalMode::Authentication;
    return p;
}
EventId append(EventStore& store, const SchedulePolicy& p, unsigned n, std::uint64_t time,
    std::string_view suffix = "ssh-failed", std::string_view unit = "ssh.service", bool indexed = true) {
    const auto row = "cursor" + std::to_string(n) + "\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + '\t' + std::string(unit) + '\t' + std::string(suffix) + '\n';
    const auto result = store.append({p.binding, unit, row, JournalMode::Authentication, time});
    require(result.status == StoreStatus::Ok, "fixture admission");
    if (indexed) { require(store.index(result.id).status == StoreStatus::Ok, "fixture index"); }
    return result.id;
}
ScheduleReport tick(const SchedulePolicy& p, const Fixture& f, const EventStore& store, std::uint64_t now,
    bool enabled = true, EvidenceTrust trust = EvidenceTrust::VerifiedStored, Coverage coverage = Coverage::Partial) {
    return run_schedule(p, f.path, store, now, enabled, trust, coverage);
}
std::string contents(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    require(file.good(), "read fixture state");
    std::string data;
    std::array<char, 4096> buffer{};
    while (file.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || file.gcount() > 0) {
        data.append(buffer.data(), static_cast<std::size_t>(file.gcount()));
        require(data.size() <= 256 * 1024, "fixture state bound");
    }
    require(file.eof() && !file.bad(), "read fixture contents");
    return data;
}
void write_fixture(const std::string& path, std::string_view value) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << value;
    file.close(); require(file.good() && ::chmod(path.c_str(), 0600) == 0, "write fixture state");
}
void restart() {
    const auto p = policy();
    Fixture f; Fixture db;
    require(initialize_schedule(p, f.path), "explicit initialization");
    require(!initialize_schedule(p, f.path), "duplicate initialization");
    EventId first{}, second{}, third{};
    {
        SqliteEventStore store(db.path);
        first = append(store, p, 1, 1000);
        append(store, p, 2, 1001, "ssh-accepted", "sshd.service");
        const auto result = tick(p, f, store, 1001, true, EvidenceTrust::VerifiedStored, Coverage::Unknown);
        require(result.status == D::Evaluated && result.observed == 1 && result.findings.empty() && result.generation == 1, "first correlation checkpoint");
        const auto before = contents(f.file());
        require(tick(p, f, store, 1002).status == D::NotDue, "interval");
        require(tick(p, f, store, 1000).status == D::Invalid, "clock regression");
        require(tick(p, f, store, 1011, false).status == D::Disabled, "disabled");
        require(tick(p, f, store, 1011, true, EvidenceTrust::Unverified).status == D::Unverified, "trust refusal");
        require(contents(f.file()) == before, "refusal mutated state");
        second = append(store, p, 3, 1010);
        third = append(store, p, 4, 1011);
    }
    const auto child = ::fork(); require(child >= 0, "fork");
    if (child == 0) {
        try {
            SqliteEventStore store(db.path, LegacyIntegrityPolicy::Reject, {}, StorageOpenMode::ExistingV4);
            const auto report = tick(p, f, store, 1011);
            const bool ok = report.status == D::Evaluated && report.findings.size() == 1 && report.suppressed == 1 &&
                report.coverage == Coverage::Unknown && report.findings.front().evidence_ids.size() == 2 &&
                report.findings.front().evidence_ids.front() == first && report.findings.front().evidence_ids.back() == second;
            ::_exit(ok ? 0 : 1);
        } catch (...) { ::_exit(2); }
    }
    int status{}; require(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child commit");
    {
        SqliteEventStore store(db.path, LegacyIntegrityPolicy::Reject, {}, StorageOpenMode::ExistingV4);
        const auto before = store.search({});
        const auto report = tick(p, f, store, 1012);
        require(report.status == D::Replay && report.generation == 2 && report.revision == before.revision &&
            report.rule_id == "ssh-failure" && report.rule_version == 1 && report.severity == RuleSeverity::Medium &&
            report.schedule_identity.size() == 64 && report.findings.size() == 1 && report.findings.front().evidence_ids.back() == second &&
            report.coverage == Coverage::Unknown && report.suppressed == 1, "persistent replay");
        require(!acknowledge_schedule(p, f.path, 1), "wrong generation");
        require(acknowledge_schedule(p, f.path, 2), "ack generation");
        require(!acknowledge_schedule(p, f.path, 2), "duplicate ack");
        require(tick(p, f, store, 1012).status == D::NotDue, "ack does not change interval");
        const auto fourth = append(store, p, 5, 1060);
        const auto resumed = tick(p, f, store, 1060);
        require(resumed.status == D::Evaluated && resumed.observed == 1 && resumed.findings.size() == 1 &&
            resumed.findings.front().evidence_ids.front() == third && resumed.findings.front().evidence_ids.back() == fourth,
            "suppression boundary and retained context");
        require(acknowledge_schedule(p, f.path, resumed.generation), "second ack");
        const auto empty = tick(p, f, store, 1070);
        require(empty.status == D::Evaluated && empty.observed == 0 && empty.findings.empty(), "dedup checkpoint");
        append(store, p, 6, 1071, "ssh-failed", "ssh.service", false);
        const auto saved = contents(f.file());
        require(tick(p, f, store, 1080).status == D::Unavailable && contents(f.file()) == saved, "pending refusal");
    }
    struct stat st{};
    require(::stat(f.file().c_str(), &st) == 0 && (st.st_mode & 07777) == 0600 && st.st_nlink == 1, "private permissions");
    const auto saved = contents(f.file());
    require(saved.find(p.binding) == std::string::npos && saved.find("ssh.service") == std::string::npos, "minimized state");
}
void negatives() {
    Fixture f; MemoryEventStore store;
    const auto p = policy();
    require(tick(p, f, store, 10).status == D::Unavailable, "missing state");
    require(initialize_schedule(p, f.path), "init");
    const auto original = contents(f.file());
    auto changed = p; changed.suppression_ms = 0;
    require(tick(changed, f, store, 10).status == D::Unavailable, "policy binding");
    changed = p; changed.store_identity = std::string(64, 'f');
    require(tick(changed, f, store, 10).status == D::Unavailable, "store binding");
    changed = p; changed.threshold = 17;
    require(tick(changed, f, store, 10).status == D::Invalid, "threshold bound");
    require(::chmod(f.file().c_str(), 0644) == 0, "change mode");
    require(tick(p, f, store, 10).status == D::Unavailable, "file mode refusal");
    require(::chmod(f.file().c_str(), 0600) == 0, "restore mode");
    const int lock = ::open(f.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(lock >= 0 && ::flock(lock, LOCK_EX | LOCK_NB) == 0, "fixture lock");
    const auto locked = tick(p, f, store, 10); ::close(lock);
    require(locked.status == D::Unavailable, "concurrent owner refusal");
    write_fixture(f.file(), original + "0\n");
    require(tick(p, f, store, 10).status == D::Unavailable, "corrupt state");
    write_fixture(f.file(), original);
    const auto link = f.path + "/hardlink";
    require(::link(f.file().c_str(), link.c_str()) == 0, "hard link fixture");
    require(tick(p, f, store, 10).status == D::Unavailable, "hard link refusal");
    require(::unlink(link.c_str()) == 0, "remove fixture link");
    require(::symlink(f.file().c_str(), f.pending().c_str()) == 0, "pending symlink");
    require(tick(p, f, store, 10).status == D::Unavailable && contents(f.file()) == original, "unsafe pending refusal");
    require(::unlink(f.pending().c_str()) == 0, "remove fixture symlink");
    write_fixture(f.pending(), "interrupted write\n");
    require(tick(p, f, store, 10).status == D::Evaluated && !std::filesystem::exists(f.pending()), "abandoned pending cleanup");
    append(store, p, 1, 100);
    const auto before = contents(f.file());
    require(tick(p, f, store, 20).status == D::Unavailable && contents(f.file()) == before, "future receiver time");
    require(tick(p, f, store, 201).expired == 1, "expired evidence");
    append(store, p, 2, 200);
    require(tick(p, f, store, 211).status == D::Evaluated, "new context");
    const auto retention = store.preview_retention(201, 32);
    require(retention.plan && store.apply_retention(*retention.plan).status == StoreStatus::Ok, "fixture retention");
    const auto retained = contents(f.file());
    require(tick(p, f, store, 221).status == D::Unavailable && contents(f.file()) == retained, "deleted context refusal");
    require(tick(p, f, store, 301).status == D::Evaluated, "expired context recovery");
}
void write_failure() {
    Fixture f; MemoryEventStore store;
    auto p = policy(); p.threshold = 1;
    require(initialize_schedule(p, f.path), "write failure init");
    append(store, p, 1, 100);
    const auto saved = contents(f.file());
    const auto child = ::fork(); require(child >= 0, "write failure fork");
    if (child == 0) {
        try {
            struct rlimit limit{};
            require(::getrlimit(RLIMIT_FSIZE, &limit) == 0, "file limit");
            limit.rlim_cur = 0;
            require(::signal(SIGXFSZ, SIG_IGN) != SIG_ERR && ::setrlimit(RLIMIT_FSIZE, &limit) == 0, "set file limit");
            const auto result = tick(p, f, store, 100);
            ::_exit(result.status == D::Unavailable && result.findings.empty() ? 0 : 1);
        } catch (...) { ::_exit(2); }
    }
    int status{}; require(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "write failure result");
    require(contents(f.file()) == saved && std::filesystem::exists(f.pending()), "failed write changed checkpoint");
    const auto retry = tick(p, f, store, 100);
    require(retry.status == D::Evaluated && retry.generation == 1 && retry.findings.size() == 1 &&
        !std::filesystem::exists(f.pending()), "write failure retry");
}
// A fault on a later page must not publish earlier matching records.
class FaultStore final : public EventStore {
public:
    enum class Fault { Stale, Duplicate, Source, EmptyMore, Pending };
    explicit FaultStore(const EventStore& delegate, Fault fault) : EventStore({}), delegate_(delegate), fault_(fault) {}
    mutable std::size_t calls{};
    ReadResult<StorageUsage> usage() const override { return delegate_.usage(); }
    Durability durability() const noexcept override { return delegate_.durability(); }
    AppendResult append(const RawInput&) override { return {}; }
    IndexResult index(EventId) override { return {}; }
    ReadResult<RawEvidence> raw(EventId) const override { throw std::runtime_error("unexpected raw read"); }
    ReadResult<NormalizedEvent> normalized(EventId) const override { throw std::runtime_error("unexpected normalized read"); }
    SearchPage search(const SearchQuery& query) const override {
        ++calls;
        auto page = delegate_.search(query);
        if (query.after == 0 || page.events.empty()) { return page; }
        switch (fault_) {
        case Fault::Stale: ++page.revision; break;
        case Fault::Duplicate: page.events.front().id = query.after; break;
        case Fault::Source: page.events.front().source_unit = "sshd.service"; break;
        case Fault::EmptyMore: page.events.clear(); page.more = true; break;
        case Fault::Pending: break;
        }
        return page;
    }
    PendingPage pending(EventId after, std::optional<std::uint64_t> revision, std::size_t limit) const override {
        return fault_ == Fault::Pending ? PendingPage{} : delegate_.pending(after, revision, limit);
    }
    StoreStatus set_hold(EventId, bool) override { return StoreStatus::Invalid; }
    RetentionPreview preview_retention(std::uint64_t, std::size_t) const override { return {}; }
    RetentionResult apply_retention(const RetentionPlan&) override { return {}; }
private:
    const EventStore& delegate_;
    Fault fault_;
};
void malformed_pages() {
    MemoryEventStore store;
    auto p = policy(); p.threshold = 1; p.suppression_ms = 0; p.window_ms = 1000;
    for (unsigned i = 1; i <= 33; ++i) { append(store, p, i, 1000 + i); }
    using F = FaultStore::Fault;
    for (const auto fault : {F::Stale, F::Duplicate, F::Source, F::EmptyMore, F::Pending}) {
        Fixture f; FaultStore invalid(store, fault);
        require(initialize_schedule(p, f.path), "fault init");
        const auto saved = contents(f.file());
        require(tick(p, f, invalid, 1100, false).status == D::Disabled && invalid.calls == 0, "disabled search");
        require(tick(p, f, invalid, 1100, true, EvidenceTrust::Unverified).status == D::Unverified && invalid.calls == 0, "unverified search");
        const auto result = tick(p, f, invalid, 1100);
        require(result.status == D::Unavailable && result.findings.empty() && result.observed == 0 &&
            invalid.calls == 2 && contents(f.file()) == saved, "partial publication on fault");
    }
}
void capacity_test() {
    Fixture f; MemoryEventStore store;
    auto p = policy(); p.threshold = 1; p.suppression_ms = 0; p.window_ms = 1000;
    require(initialize_schedule(p, f.path), "capacity init");
    for (unsigned i = 1; i <= 128; ++i) { append(store, p, i, 1000 + i); }
    const auto r = tick(p, f, store, 1200);
    require(r.status == D::Evaluated && r.observed == 128 && r.findings.size() == 128 &&
        r.findings.front().evidence_ids.front() == 1 && r.findings.back().evidence_ids.front() == 128, "four page bounded scan");
    const auto again = tick(p, f, store, 1201);
    require(again.status == D::Replay && again.findings == r.findings && again.generation == r.generation, "capacity replay");
}
} // namespace
int main() {
    ::umask(0077);
    try { restart(); negatives(); write_failure(); malformed_pages(); capacity_test(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    std::cout << "M7.5 durable scheduling, cross-process replay, suppression, correlation and duplicate management: PASS\n";
    std::cout << "M7.5 protected state, refusal, retention and bounded pagination: PASS\n";
    return 0;
}

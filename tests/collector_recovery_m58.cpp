// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/journal.hpp"
#include <algorithm>
#include <array>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {
using namespace knetsentry::agent;
namespace fs = std::filesystem;
void require(bool ok, const char* reason) { if (!ok) { throw std::runtime_error(reason); } }
struct Temp final {
    fs::path path;
    Temp() {
        std::array<char, 24> pattern{"/tmp/ks-recovery-XXXXXX"};
        const auto* result = ::mkdtemp(pattern.data());
        require(result != nullptr, "temporary directory failed");
        path = result;
    }
    ~Temp() { std::error_code error; fs::remove_all(path, error); }
};
struct Source final : JournalSource {
    std::vector<JournalRecord> records;
    std::size_t position{}, opens{}, reads{};
    bool available{true}, opened{}, seekable{true}, error_at_end{};
    bool open(std::string_view) override { ++opens; opened = available; return opened; }
    bool resume(std::string_view cursor) override {
        if (!opened || !seekable) { return false; }
        position = 0;
        if (cursor.empty()) { return true; }
        const auto it = std::ranges::find(records, cursor, &JournalRecord::cursor);
        if (it == records.end()) { return false; }
        position = static_cast<std::size_t>(it - records.begin()) + 1;
        return true;
    }
    JournalResult next(JournalRecord& record) override {
        ++reads;
        if (!opened) { return JournalResult::Error; }
        if (position == records.size()) { return error_at_end ? JournalResult::Error : JournalResult::End; }
        record = records.at(position++);
        return JournalResult::Record;
    }
    void close() noexcept override { opened = false; }
};
struct Profile {
    JournalMode mode;
    const char* unit;
    const char* state;
    const char* pending;
    bool redact;
};
constexpr std::array profiles{
    Profile{JournalMode::Metadata, "fixture.service", "journal-m52.v1", "journal-m52.pending", false},
    Profile{JournalMode::Authentication, "ssh.service", "auth-m53.v1", "auth-m53.pending", false},
    Profile{JournalMode::Authentication, "ssh.service", "auth-m53.v1", "auth-m53.pending", true},
    Profile{JournalMode::Audit, "audit", "audit-m54.v1", "audit-m54.pending", false},
};
// Synthetic identifiers require no dynamic global initialization.
constexpr char fingerprint[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr char binding[] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static_assert(sizeof(fingerprint) == 65); // Includes the terminating NUL.
static_assert(sizeof(binding) == 97);
JournalRecord event(const Profile& profile, std::size_t n) {
    JournalRecord r{"cursor-" + std::to_string(n), profile.unit,
        "1234567890abcdef1234567890abcdef", "abcdef1234567890abcdef1234567890",
        1700000000000000ULL + n, n};
    if (profile.mode == JournalMode::Authentication) { r.auth = profile.redact ? AuthEvent::Redacted : AuthEvent::SshAccepted; }
    if (profile.mode == JournalMode::Audit) { r.audit_type = 1300; r.audit_id = n; }
    return r;
}
std::string read(const fs::path& file) {
    std::ifstream input(file);
    require(input.is_open(), "fixture read failed");
    std::string content;
    std::array<char, 4096> bytes{};
    while (input.read(bytes.data(), static_cast<std::streamsize>(bytes.size())) || input.gcount() > 0) {
        content.append(bytes.data(), static_cast<std::size_t>(input.gcount()));
    }
    require(input.eof() && !input.bad(), "fixture read failed");
    return content;
}
void save(const fs::path& file, const std::string& content) {
    std::ofstream output(file); output << content; output.close();
    require(output.good() && ::chmod(file.c_str(), 0600) == 0, "fixture write failed");
}
std::string row_for(const std::string& state, std::string_view cursor) {
    const auto begin = state.find(std::string(cursor) + '\t');
    require(begin != state.npos, "missing expected row");
    const auto end = state.find('\n', begin);
    require(end != state.npos, "unterminated row");
    return state.substr(begin, end - begin + 1);
}
void recover(const Profile& p, bool buffered) {
    Temp temp;
    const auto path = temp.path.string();
    const auto state = temp.path / (buffered ? "telemetry-m55.v1" : p.state);
    const auto pending = temp.path / (buffered ? "telemetry-m55.pending" : p.pending);
    const auto destination = buffered ? std::string{binding} : std::string{};
    Source source;
    source.records = {event(p, 1), event(p, 2)};
    {
        JournalCollector c(source, p.unit, path, p.mode, destination, fingerprint, p.redact);
        require(c.start() && c.pump() && c.count() == 2, "seed collection");
    }
    const auto original = read(state);
    source.records.push_back(event(p, 3));
    source.error_at_end = true;
    {
        JournalCollector c(source, p.unit, path, p.mode, destination, fingerprint, p.redact);
        require(c.start() && !c.pump() && c.count() == 3, "source error after valid prefix");
        require(c.collection_blocked() == buffered && c.source_failed(), "source failure profile mismatch");
        const auto reads = source.reads;
        require(!c.pump() && reads == source.reads, "failed source still consumed");
    }
    const auto committed = read(state);
    require(row_for(original, "cursor-1") == row_for(committed, "cursor-1") &&
        row_for(original, "cursor-2") == row_for(committed, "cursor-2") &&
        !row_for(committed, "cursor-3").empty(), "valid prefix lost");
    source.error_at_end = false;
    // A bad record or nonadjacent duplicate must fail on every restart, not be skipped.
    for (const bool duplicate : {false, true}) {
        auto bad = event(p, duplicate ? 1U : 4U);
        if (!duplicate) { bad.realtime_usec = 0; }
        source.records = {event(p, 1), event(p, 2), event(p, 3), bad, event(p, 5)};
        for (int retry = 0; retry < 2; ++retry) {
            JournalCollector c(source, p.unit, path, p.mode, destination, fingerprint, p.redact);
            require(c.start() && !c.pump() && c.source_failed() && read(state) == committed && source.position == 4,
                "invalid record advanced checkpoint or consumed later record");
        }
    }
    // No source access at all for invalid persistent state or permissions.
    const auto opens = source.opens;
    save(state, committed + row_for(committed, "cursor-1"));
    const auto corrupt = read(state);
    {
        JournalCollector c(source, p.unit, path, p.mode, destination, fingerprint, p.redact);
        require(!c.start() && !c.source_failed() && read(state) == corrupt && source.opens == opens, "duplicate state accepted");
    }
    save(state, committed);
    require(::chmod(state.c_str(), 0644) == 0, "fixture chmod");
    {
        JournalCollector c(source, p.unit, path, p.mode, destination, fingerprint, p.redact);
        require(!c.start() && !c.source_failed() && source.opens == opens && read(state) == committed, "unsafe state permissions accepted");
    }
    require(::chmod(state.c_str(), 0600) == 0, "restore fixture mode");
    source.records = {event(p, 1), event(p, 2), event(p, 3), event(p, 4)};
    {
        JournalCollector c(source, p.unit, path, p.mode, destination, fingerprint, p.redact);
        require(c.start(), "collision setup");
        save(pending, "synthetic incomplete transaction");
        require(!c.pump() && !c.source_failed() && read(state) == committed && read(pending) == "synthetic incomplete transaction",
            "exclusive pending collision altered evidence");
    }
    // Refuse an unsafe pending object; do not follow it or remove it.
    fs::remove(pending);
    const auto target = temp.path / "unapproved";
    save(target, "synthetic canary");
    fs::create_symlink(target, pending);
    const auto before_open = source.opens;
    {
        JournalCollector c(source, p.unit, path, p.mode, destination, fingerprint, p.redact);
        require(!c.start() && source.opens == before_open && fs::is_symlink(pending) &&
            read(target) == "synthetic canary" && read(state) == committed, "unsafe pending accepted");
    }
    fs::remove(pending);
    save(pending, "synthetic interrupted transaction");
    {
        JournalCollector c(source, p.unit, path, p.mode, destination, fingerprint, p.redact);
        require(c.start() && !fs::exists(pending) && c.pump() && c.count() == 4, "safe transaction recovery failed");
        require(c.pump() && c.count() == 4, "EOF duplicated evidence");
    }
    const auto recovered = read(state);
    require(row_for(recovered, "cursor-3") == row_for(committed, "cursor-3") &&
        !row_for(recovered, "cursor-4").empty(), "recovery lost valid evidence");
    // Stale checkpoint is terminal for local stores, blocked for buffered stores.
    source.seekable = false;
    {
        JournalCollector c(source, p.unit, path, p.mode, destination, fingerprint, p.redact);
        require(c.start() == buffered && c.collection_blocked() == buffered && c.source_failed() && !c.pump() &&
            read(state) == recovered, "stale cursor changed evidence");
    }
    source.seekable = true;
    source.available = false;
    {
        JournalCollector c(source, p.unit, path, p.mode, destination, fingerprint, p.redact);
        require(c.start() == buffered && c.collection_blocked() == buffered && c.source_failed() && !c.pump() &&
            read(state) == recovered, "unavailable source changed evidence");
    }
    source.available = true;
    {
        JournalCollector c(source, p.unit, path, p.mode, destination, fingerprint, p.redact);
        require(c.start(), "permission change setup");
        const auto reads = source.reads;
        require(::chmod(temp.path.c_str(), 0755) == 0, "directory chmod");
        const bool rejected = !c.pump();
        require(::chmod(temp.path.c_str(), 0700) == 0, "restore directory mode");
        require(rejected && !c.source_failed() && source.reads == reads && read(state) == recovered, "unsafe directory consumed source");
    }
}
void disconnected_crash() {
    Temp temp;
    const auto& p = profiles.front();
    const auto state = temp.path / "telemetry-m55.v1";
    const auto pending = temp.path / "telemetry-m55.pending";
    Source source;
    for (std::size_t n = 1; n <= JournalCollector::max_records + 1; ++n) { source.records.push_back(event(p, n)); }
    // Kill a real child holding the store lock after a known durable boundary.
    // Pending content is fixture-injected, not a timed interruption inside fsync.
    const auto child = ::fork();
    require(child >= 0, "fork failed");
    if (child == 0) {
        try {
            JournalCollector c(source, p.unit, temp.path.string(), p.mode, binding, fingerprint);
            require(c.start() && c.pump() && c.count() == JournalCollector::batch_size, "child seed");
            save(pending, "synthetic abandoned transaction");
            if (::raise(SIGSTOP) != 0) { std::_Exit(3); }
        } catch (...) { std::_Exit(2); }
        std::_Exit(4);
    }
    int status{};
    require(::waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status), "child did not reach crash boundary");
    const int killed = ::kill(child, SIGKILL);
    const auto waited = ::waitpid(child, &status, 0);
    require(killed == 0 && waited == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "child crash failed");
    const auto before = read(state);
    {
        JournalCollector c(source, p.unit, temp.path.string(), p.mode, binding, fingerprint);
        require(c.start() && c.count() == JournalCollector::batch_size && !fs::exists(pending) &&
            read(state) == before, "crash recovery lost committed state or lock");
        for (std::size_t n = JournalCollector::batch_size; n < JournalCollector::max_records; n += JournalCollector::batch_size) {
            require(c.pump(), "fill disconnected outbox");
        }
        require(c.backpressured() && c.count() == JournalCollector::max_records && source.position == JournalCollector::max_records,
            "queue exceeded capacity");
        const auto reads = source.reads;
        const auto full = read(state);
        for (int n = 0; n < 3; ++n) {
            require(c.pump() && source.reads == reads && read(state) == full, "backpressure consumed or changed evidence");
        }
    }
    const auto full = read(state);
    {
        JournalCollector c(source, p.unit, temp.path.string(), p.mode, binding, fingerprint);
        const auto reads = source.reads;
        require(c.start() && c.backpressured() && c.pump() && source.reads == reads && read(state) == full,
            "full queue restart consumed evidence");
    }
}
} // namespace
int main() {
    ::umask(0077);
    try {
        require(::geteuid() != 0, "run synthetic recovery tests as an ordinary user");
        for (const auto& p : profiles) {
            recover(p, false);
            recover(p, true);
        }
        std::cout << "M5.8 eight policy-bound profiles: source errors, invalid/duplicate records, permissions and transaction recovery: PASS\n";
        disconnected_crash();
        std::cout << "M5.8 SIGKILL restart, committed prefix, abandoned pending state, lock recovery and disconnected backpressure: PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "M5.8 recovery fixture failure: " << error.what() << '\n'; return 1; }
}

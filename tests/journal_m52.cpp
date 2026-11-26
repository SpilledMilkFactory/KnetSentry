// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/journal.hpp"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
using namespace knetsentry::agent;
namespace fs = std::filesystem;
constexpr auto unit = "fixture.service";
constexpr auto machine = "1234567890abcdef1234567890abcdef";
constexpr auto boot = "abcdef1234567890abcdef1234567890";
void require(bool ok, const char* reason) { if (!ok) { throw std::runtime_error(reason); } }
struct Temp final {
    fs::path path;
    Temp() {
        std::array<char, 25> pattern{"/tmp/ks-journal-XXXXXX"};
        const auto* result = ::mkdtemp(pattern.data());
        require(result != nullptr, "temporary directory failed");
        path = result;
    }
    ~Temp() { std::error_code error; fs::remove_all(path, error); }
};
struct Source final : JournalSource {
    std::vector<JournalRecord> records;
    std::size_t index{};
    bool opened{};
    bool open(std::string_view selected) override { opened = selected == unit; return opened; }
    bool resume(std::string_view cursor) override {
        index = 0;
        if (cursor.empty()) { return opened; }
        const auto it = std::ranges::find(records, cursor, &JournalRecord::cursor);
        if (it == records.end()) { return false; }
        index = static_cast<std::size_t>(it - records.begin()) + 1;
        return opened;
    }
    JournalResult next(JournalRecord& record) override {
        if (!opened) { return JournalResult::Error; }
        if (index == records.size()) { return JournalResult::End; }
        record = records.at(index++);
        return JournalResult::Record;
    }
    void close() noexcept override { opened = false; }
};
JournalRecord event(std::size_t n) {
    return {"cursor-" + std::to_string(n), unit, machine, boot, 1700000000000000ULL + n, n};
}
std::string read(const fs::path& file) {
    std::ifstream in(file);
    require(in.is_open(), "fixture read failed");
    std::string data;
    std::array<char, 4096> buffer{};
    while (in.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || in.gcount() > 0) {
        data.append(buffer.data(), static_cast<std::size_t>(in.gcount()));
    }
    require(in.eof() && !in.bad(), "fixture read failed");
    return data;
}
void save(const fs::path& file, const std::string& content) {
    std::ofstream out(file); out << content; out.close();
    require(out.good() && ::chmod(file.c_str(), 0600) == 0, "fixture write failed");
}
void contract() {
    Temp temp;
    const auto path = temp.path.string();
    const auto state = temp.path / "journal-m52.v1";
    const auto pending = temp.path / "journal-m52.pending";
    Source source;
    source.records = {event(1), event(2)};
    require(valid_journal_unit(unit) && !valid_journal_unit("*.service") &&
        !valid_journal_unit("bad\n.service") && !valid_journal_directory("/tmp/../home") &&
        !valid_journal_directory("relative"), "unsafe config accepted");
    {
        JournalCollector collector(source, unit, path);
        require(collector.start() && collector.pump() && collector.count() == 2, "initial collection failed");
        Source other;
        JournalCollector busy(other, unit, path);
        require(!busy.start(), "concurrent writer accepted");
        require(collector.pump() && collector.count() == 2, "EOF duplicated records");
    }
    const auto first = read(state);
    require(first.find("cursor-1\t1700000000000001\t1\t") != std::string::npos &&
            first.find(machine) != std::string::npos && first.find(boot) != std::string::npos,
            "timestamp/provenance missing");
    save(pending, "uncommitted data");
    source.records.push_back(event(3));
    {
        JournalCollector collector(source, unit, path);
        require(collector.start() && collector.pump() && collector.count() == 3, "restart failed");
        require(!fs::exists(pending), "pending state not recovered");
    }
    const auto second = read(state);
    require(second.starts_with(first) && second.find("cursor-3\t") != std::string::npos, "checkpoint lost records");
    source.records = {event(4)};
    {
        JournalCollector collector(source, unit, path);
        require(!collector.start() && read(state) == second, "stale cursor silently reset");
    }
    source.records = {event(3), event(4)};
    source.records.back().unit = "other.service";
    {
        JournalCollector collector(source, unit, path);
        require(collector.start() && !collector.pump() && read(state) == second, "wrong unit stored");
    }
    for (int invalid = 0; invalid < 4; ++invalid) {
        source.records = {event(3), event(4)};
        auto& bad = source.records.back();
        if (invalid == 0) { bad.realtime_usec = 0; }
        else if (invalid == 1) { bad.monotonic_usec = std::uint64_t{1} << 55; }
        else if (invalid == 2) { bad.machine = "invalid-id"; }
        else { bad.cursor = "invalid\tfield"; }
        JournalCollector collector(source, unit, path);
        require(collector.start() && !collector.pump() && read(state) == second, "malformed record committed");
    }
    source.records = {event(3), event(1)};
    {
        JournalCollector collector(source, unit, path);
        require(collector.start() && !collector.pump() && read(state) == second, "nonadjacent duplicate stored");
    }
    {
        JournalCollector collector(source, "other.service", path);
        require(!collector.start(), "scope change silently accepted");
    }
    require(::chmod(state.c_str(), 0644) == 0, "chmod failed");
    {
        JournalCollector collector(source, unit, path);
        require(!collector.start(), "public state accepted");
    }
    require(::chmod(state.c_str(), 0600) == 0, "chmod failed");
    fs::remove(state);
    save(state, second + "partial");
    {
        JournalCollector collector(source, unit, path);
        require(!collector.start(), "corrupt state accepted");
    }
    fs::remove(state);
    const auto target = temp.path / "target";
    save(target, "untouched");
    fs::create_symlink(target, state);
    {
        JournalCollector collector(source, unit, path);
        require(!collector.start() && read(target) == "untouched", "symlink accepted");
    }
    fs::remove(state);
    fs::create_hard_link(target, state);
    {
        JournalCollector collector(source, unit, path);
        require(!collector.start() && read(target) == "untouched", "hardlink accepted");
    }
    fs::remove(state);
    source.records.clear();
    for (std::size_t i = 1; i <= JournalCollector::max_records + 1; ++i) { source.records.push_back(event(i)); }
    {
        JournalCollector collector(source, unit, path);
        require(collector.start(), "capacity fixture start failed");
        require(collector.pump() && collector.count() == JournalCollector::batch_size, "batch limit failed");
        for (std::size_t i = 1; i < JournalCollector::max_records / JournalCollector::batch_size; ++i) {
            require(collector.pump(), "capacity fixture pump failed");
        }
        const auto full = read(state);
        require(collector.count() == JournalCollector::max_records && !collector.pump() &&
            read(state) == full, "capacity silently discarded data");
    }
    std::cout << "M5.2 timestamps, provenance, cursor restart, stale cursor, invalid scope, atomic pending recovery, locking, file safety and capacity: PASS\n";
}
void native(const std::string& directory, bool populated) {
    Temp state;
    auto source = make_journal_source(directory);
    JournalCollector collector(*source, unit, state.path.string());
    require(collector.start() && collector.pump(), "native journal open/read failed");
    require(collector.count() == (populated ? 2U : 0U), "native selection/count mismatch");
    if (populated) {
        const auto data = read(state.path / "journal-m52.v1");
        require(data.find(machine) != std::string::npos && data.find(boot) != std::string::npos &&
            data.find("1700000000000001\t1\t") != std::string::npos &&
            data.find("1700000000000003\t3\t") != std::string::npos &&
            data.find("excluded.service") == std::string::npos &&
            data.find("private-canary") == std::string::npos,
            "native provenance or privacy mismatch");
    }
    collector.stop();
    const auto file = state.path / "journal-m52.v1";
    if (populated) {
        const auto complete = read(file);
        const auto header_end = complete.find('\n');
        const auto first_end = complete.find('\n', header_end + 1);
        require(header_end != std::string::npos && first_end != std::string::npos, "native fixture rows missing");
        // Simulate a prior durable transaction containing only the first selected entry.
        save(file, complete.substr(0, first_end + 1));
        {
            JournalCollector resume(*source, unit, state.path.string());
            require(resume.start() && resume.pump() && resume.count() == 2 && read(file) == complete,
                    "native exact resume did not recover second selected entry");
        }
        Temp missing;
        auto empty = make_journal_source(missing.path.string());
        JournalCollector stale(*empty, unit, state.path.string());
        require(!stale.start() && read(file) == complete, "native missing cursor silently reset");
    }
    JournalCollector restart(*source, unit, state.path.string());
    require(restart.start() && restart.pump() && restart.count() == (populated ? 2U : 0U), "native restart failed");
    Temp buffered;
    const std::string binding(96, 'a');
    auto buffered_source = make_journal_source(directory);
    {
        JournalCollector queue(*buffered_source, unit, buffered.path.string(), JournalMode::Metadata, binding);
        require(queue.start() && queue.pump() && queue.count() == (populated ? 2U : 0U), "native buffered collection");
    }
    const auto buffer_file = buffered.path / "telemetry-m55.v1";
    if (populated) {
        const auto data = read(buffer_file);
        require(data.starts_with("KNETSENTRY-OUTBOX-V1\t" + binding) && data.find("private-canary") == std::string::npos,
            "native buffered format or privacy");
        JournalCollector queue(*buffered_source, unit, buffered.path.string(), JournalMode::Metadata, binding);
        require(queue.start() && queue.pump() && queue.count() == 2 && read(buffer_file) == data, "native buffered restart");
    } else { require(!fs::exists(buffer_file), "empty native buffered source fabricated evidence"); }
    std::cout << "M5.2 native journal selection and restart; M5.5 native buffered recovery: PASS\n";
}
} // namespace
int main(int argc, char** argv) {
    ::umask(0077);
    try {
        if (argc == 2) { native(argv[1], true); }
        else if (argc == 1) { contract(); Temp empty; native(empty.path.string(), false); }
        else { return 2; }
        return 0;
    } catch (const std::exception& error) { std::cerr << "M5.2 fixture failure: " << error.what() << '\n'; return 1; }
}

// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/journal.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <cstdlib>

namespace {
using namespace knetsentry::agent;
namespace fs = std::filesystem;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
struct Temp final {
    fs::path path;
    Temp() {
        std::array<char, 24> pattern{"/tmp/ks-audit-XXXXXX"};
        const auto* result = ::mkdtemp(pattern.data());
        require(result != nullptr, "temporary directory failed");
        path = result;
    }
    ~Temp() { std::error_code error; fs::remove_all(path, error); }
};
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
void save(const fs::path& file, const std::string& data) {
    std::ofstream out(file); out << data; out.close();
    require(out.good() && ::chmod(file.c_str(), 0600) == 0, "fixture write failed");
}
class MissingSource final : public JournalSource {
public:
    bool open(std::string_view) override { return false; }
    bool resume(std::string_view) override { return false; }
    JournalResult next(JournalRecord&) override { return JournalResult::Error; }
    void close() noexcept override {}
};
void native(const std::string& directory, const std::string& bad_directory) {
    Temp state;
    const auto file = state.path / "audit-m54.v1";
    auto source = make_journal_source(directory, JournalMode::Audit);
    {
        JournalCollector collector(*source, "audit", state.path.string(), JournalMode::Audit);
        require(collector.start() && collector.pump() && collector.count() == 3, "native audit selection failed");
        require(collector.pump() && collector.count() == 3, "duplicate audit record");
    }
    const auto complete = read(file);
    const std::string header = "KNETSENTRY-AUDIT-V1\taudit\n";
    require(complete.starts_with(header) && complete.find("private-") == std::string::npos &&
        complete.find("MESSAGE") == std::string::npos && complete.find("uid=") == std::string::npos,
        "audit privacy boundary failed");
    std::string_view rows(complete);
    rows.remove_prefix(header.size());
    constexpr std::array<std::string_view, 3> expected{
        "\t1700000000000001\t1\t1234567890abcdef1234567890abcdef\tabcdef1234567890abcdef1234567890\taudit\t1300\t42",
        "\t1700000000000003\t3\t1234567890abcdef1234567890abcdef\tabcdef1234567890abcdef1234567890\taudit\t1302\t42",
        "\t1700000000000004\t4\t1234567890abcdef1234567890abcdef\tabcdef1234567890abcdef1234567890\taudit\t1100\t43"};
    for (const auto suffix : expected) {
        const auto end = rows.find('\n');
        require(end != rows.npos && rows.substr(0, end).ends_with(suffix), "native audit metadata mismatch");
        rows.remove_prefix(end + 1);
    }
    require(rows.empty(), "unexpected native records");
    const auto first = complete.find('\n', header.size());
    require(first != complete.npos, "missing initial checkpoint");
    save(file, complete.substr(0, first + 1));
    {
        JournalCollector collector(*source, "audit", state.path.string(), JournalMode::Audit);
        require(collector.start() && collector.pump() && collector.count() == 3, "exact audit recovery failed");
    }
    require(read(file) == complete, "recovered state differs");
    {
        JournalCollector collector(*source, "audit", state.path.string(), JournalMode::Audit);
        require(collector.start() && collector.pump() && collector.count() == 3, "audit restart failed");
    }
    require(read(file) == complete, "restart altered state");
    auto malformed = complete;
    malformed.replace(malformed.rfind("1100"), 4, "0000");
    save(file, malformed);
    {
        JournalCollector collector(*source, "audit", state.path.string(), JournalMode::Audit);
        require(!collector.start(), "invalid persisted audit type accepted");
    }
    require(read(file) == malformed, "invalid state rewritten");
    save(file, complete);
    Temp empty;
    auto empty_source = make_journal_source(empty.path.string(), JournalMode::Audit);
    {
        JournalCollector collector(*empty_source, "audit", state.path.string(), JournalMode::Audit);
        require(!collector.start(), "stale audit checkpoint accepted");
    }
    require(read(file) == complete, "stale checkpoint changed evidence");
    Temp empty_state;
    {
        JournalCollector collector(*empty_source, "audit", empty_state.path.string(), JournalMode::Audit);
        require(collector.start() && collector.pump() && collector.count() == 0, "empty audit source not handled");
    }
    require(!fs::exists(empty_state.path / "audit-m54.v1"), "empty source fabricated evidence");
    MissingSource missing;
    {
        JournalCollector collector(missing, "audit", empty_state.path.string(), JournalMode::Audit);
        require(!collector.start() && std::string_view(collector.error()) == "journal open failed", "source failure not handled");
    }
    require(!fs::exists(empty_state.path / "audit-m54.v1"), "missing source fabricated evidence");
    Temp bad_state;
    auto bad_source = make_journal_source(bad_directory, JournalMode::Audit);
    const auto bad_file = bad_state.path / "audit-m54.v1";
    {
        JournalCollector collector(*bad_source, "audit", bad_state.path.string(), JournalMode::Audit);
        require(collector.start() && !collector.pump() && collector.count() == 2,
                "missing native audit ID did not stop collection");
        require(!collector.pump(), "failed collector resumed");
    }
    const auto partial = read(bad_file);
    require(partial.starts_with(header) && partial.ends_with("\taudit\t1302\t42\n"),
            "malformed native record advanced checkpoint");
    {
        JournalCollector collector(*bad_source, "audit", bad_state.path.string(), JournalMode::Audit);
        require(collector.start() && !collector.pump() && collector.count() == 2,
                "malformed native record silently skipped at restart");
    }
    require(read(bad_file) == partial, "failed recovery changed evidence");
    std::cout << "M5.4 native audit selection, multipart IDs, privacy, timestamps, restart and unavailable source: PASS\n";
    std::cout << "M5.4 malformed native audit record preserves checkpoint and rejects retry: PASS\n";
}
} // namespace
int main(int argc, char** argv) {
    try {
        require(argc == 3, "fixture directories required");
        std::uint64_t value{};
        require(parse_audit_number("18446744073709551615", value) && value == UINT64_MAX, "valid audit number rejected");
        for (const auto* bad : {"", "-1", "+1", "01", "1x", "1\n", "18446744073709551616"}) {
            require(!parse_audit_number(bad, value), "invalid audit number accepted");
        }
        native(argv[1], argv[2]);
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

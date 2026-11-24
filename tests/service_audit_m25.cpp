// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/audit.hpp"

#include <array>
#include <bit>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using knetsentry::service::AuditEvent;
using knetsentry::service::AuditLog;
using knetsentry::service::AuditActor;

int main() {
    std::array<char, 32> path{"/tmp/ks-audit-unit-XXXXXX"};
    if (::mkdtemp(path.data()) == nullptr) { return 1; }
    const std::filesystem::path dir(path.data());
    const auto file = dir / "service-audit.jsonl";
    bool passed = true;
    const auto require = [&](bool ok, const char* label) {
        if (!ok) { std::cerr << label << '\n'; passed = false; }
    };
    {
        AuditLog log;
        require(log.open(path.data()), "open private audit");
        require(log.record(AuditEvent::Starting), "initial write");
        require(log.record(AuditEvent::StatusAuthorized,
            AuditActor{::getpid(), ::geteuid(), ::getegid()}), "peer record");
        require(!log.record(std::bit_cast<AuditEvent>(std::uint8_t{255})), "invalid event rejected");
        require(!log.ok() && !log.record(AuditEvent::Stopped), "sticky failure");
    }
    {
        std::ifstream input(file);
        std::string line;
        int count = 0;
        while (std::getline(input, line)) {
            require(line.size() < AuditLog::max_record, "record bound");
            ++count;
        }
        require(count == 2, "failed write did not append");
        AuditLog duplicate;
        require(!duplicate.open(path.data()), "existing file refused");
    }
    std::filesystem::remove(file);
    {
        AuditLog log;
        require(log.open(path.data()), "capacity fixture open");
        std::size_t count = 0;
        while (count < 10000 && log.record(AuditEvent::RequestRejected)) { ++count; }
        require(count > 0 && count < 10000 && !log.ok(), "finite file budget");
        const auto size = std::filesystem::file_size(file);
        require(size <= AuditLog::max_bytes && AuditLog::max_bytes - size < AuditLog::max_record,
            "file budget enforced before append");
        require(!log.record(AuditEvent::Stopped) && std::filesystem::file_size(file) == size,
            "no writes after capacity failure");
    }
    std::filesystem::remove_all(dir);
    return passed ? 0 : 1;
}

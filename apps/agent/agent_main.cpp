// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/lifecycle.hpp"
#include "knetsentry/agent/journal.hpp"
#include <cerrno>
#include <array>
#include <csignal>
#include <iostream>
#include <linux/capability.h>
#include <string_view>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {
// Returns a fixed diagnostic on failure; no caller-controlled values are logged.
[[nodiscard]] const char* restrict_privileges() noexcept {
    uid_t real{}, effective{}, saved{};
    gid_t group{}, effective_group{}, saved_group{};
    if (::getresuid(&real, &effective, &saved) != 0 ||
        ::getresgid(&group, &effective_group, &saved_group) != 0) {
        return "identity query failed";
    }
    if (real == 0 || effective != real || saved != real ||
        group == 0 || effective_group != group || saved_group != group) {
        return "zero or mismatched identity";
    }
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    std::array<__user_cap_data_struct, _LINUX_CAPABILITY_U32S_3> data{};
    if (::syscall(SYS_capget, &header, data.data()) != 0) {
        return "capability query failed";
    }
    bool inherited = false;
    for (const auto& word : data) {
        if (word.effective != 0 || word.permitted != 0) {
            return "active capability authority";
        }
        inherited = inherited || word.inheritable != 0;
    }
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0 ||
        ::prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) != 1) {
        return "no-new-privileges setup failed";
    }
    // Login environments may carry inheritable-only bits. Remove, never grant,
    // capabilities. Ambient bits are necessarily a subset of permitted and
    // inheritable bits, so an empty permitted set also excludes ambient bits.
    if (inherited) {
        data = {};
        if (::syscall(SYS_capset, &header, data.data()) != 0) {
            return "inheritable capability removal failed";
        }
    }
    if (::syscall(SYS_capget, &header, data.data()) != 0) {
        return "capability readback failed";
    }
    for (const auto& word : data) {
        if (word.effective != 0 || word.permitted != 0 || word.inheritable != 0) {
            return "nonempty capability readback";
        }
    }
    return nullptr;
}
int run(std::string_view unit = {}, std::string_view directory = {},
        knetsentry::agent::JournalMode mode = knetsentry::agent::JournalMode::Metadata) {
    if (const auto* reason = restrict_privileges(); reason != nullptr) {
        std::cerr << "knetsentry-agent: privilege policy rejected: " << reason << '\n';
        return 3;
    }
    ::umask(0077);
    sigset_t signals{};
    if (::sigemptyset(&signals) != 0 || ::sigaddset(&signals, SIGTERM) != 0 ||
        ::sigaddset(&signals, SIGINT) != 0 || ::sigprocmask(SIG_BLOCK, &signals, nullptr) != 0) {
        std::cerr << "knetsentry-agent: signal setup failed\n";
        return 1;
    }
    auto source = unit.empty() ? nullptr : knetsentry::agent::make_journal_source({}, mode);
    std::unique_ptr<knetsentry::agent::JournalCollector> journal;
    if (source) {
        journal = std::make_unique<knetsentry::agent::JournalCollector>(
            *source, std::string(unit), std::string(directory), mode);
    }
    knetsentry::agent::Lifecycle lifecycle;
    const std::array<knetsentry::agent::Collector*, 1> modules{journal.get()};
    if (!lifecycle.start(journal ? std::span<knetsentry::agent::Collector* const>(modules) :
                                   std::span<knetsentry::agent::Collector* const>{})) {
        if (journal) { std::cerr << "knetsentry-agent: journal rejected: " << journal->error() << '\n'; }
        return 1;
    }
    if (journal) {
        std::cout << (mode == knetsentry::agent::JournalMode::Authentication ?
            "knetsentry-agent: ready; collectors=1; journal=local-authentication; monitoring=unavailable; network=disabled\n" :
            "knetsentry-agent: ready; collectors=1; journal=local-metadata; monitoring=unavailable; network=disabled\n") << std::flush;
    } else {
        std::cout << "knetsentry-agent: ready; collectors=0; monitoring=unavailable; network=disabled\n" << std::flush;
    }
    if (!std::cout) { return 1; }
    if (journal) {
        for (;;) {
            if (!journal->pump()) {
                std::cerr << "knetsentry-agent: journal rejected: " << journal->error() << '\n';
                return 1;
            }
            const timespec delay{1, 0};
            const int signal = ::sigtimedwait(&signals, nullptr, &delay);
            if (signal == SIGINT || signal == SIGTERM) { break; }
            if (signal < 0 && (errno == EAGAIN || errno == EINTR)) { continue; }
            return 1;
        }
    } else {
        int signal{};
        if (::sigwait(&signals, &signal) != 0) { return 1; }
    }
    lifecycle.stop();
    std::cout << "knetsentry-agent: stopped\n" << std::flush;
    return std::cout ? 0 : 1;
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "Usage: knetsentry-agent --run --schema-version 1 --collectors none\n       knetsentry-agent --run --schema-version 1 --collectors journal --unit NAME.service --state-dir /absolute/private/directory\n       knetsentry-agent --run --schema-version 1 --collectors authentication --unit NAME.service --state-dir /absolute/private/directory\n";
        return 0;
    }
    if (argc == 10 && std::string_view(argv[1]) == "--run" &&
        std::string_view(argv[2]) == "--schema-version" && std::string_view(argv[3]) == "1" &&
        std::string_view(argv[4]) == "--collectors" && (std::string_view(argv[5]) == "journal" ||
         (std::string_view(argv[5]) == "authentication" && knetsentry::agent::valid_auth_unit(argv[7]))) &&
        std::string_view(argv[6]) == "--unit" && std::string_view(argv[8]) == "--state-dir" &&
        knetsentry::agent::valid_journal_unit(argv[7]) && knetsentry::agent::valid_journal_directory(argv[9])) {
        try { return run(argv[7], argv[9], std::string_view(argv[5]) == "authentication" ?
            knetsentry::agent::JournalMode::Authentication : knetsentry::agent::JournalMode::Metadata); }
        catch (...) { std::cerr << "knetsentry-agent: journal startup failed\n"; return 1; }
    }
    if (argc != 6 || std::string_view(argv[1]) != "--run") {
        std::cerr << "knetsentry-agent: configuration rejected\n";
        return 2;
    }
    const std::array<std::string_view, 4> args{argv[2], argv[3], argv[4], argv[5]};
    if (!knetsentry::agent::valid_configuration(args)) {
        std::cerr << "knetsentry-agent: configuration rejected\n";
        return 2;
    }
    return run();
}

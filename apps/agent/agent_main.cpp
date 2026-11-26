// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/lifecycle.hpp"
#include "knetsentry/agent/journal.hpp"
#include "knetsentry/agent/fim.hpp"
#include <algorithm>
#include <utility>
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
        knetsentry::agent::JournalMode mode = knetsentry::agent::JournalMode::Metadata,
        std::string_view binding = {}, std::vector<std::string> paths = {}) {
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
            *source, std::string(unit), std::string(directory), mode, std::string(binding));
    }
    std::unique_ptr<knetsentry::agent::IntegrityCollector> fim;
    if (!paths.empty()) { fim = std::make_unique<knetsentry::agent::IntegrityCollector>(std::move(paths)); }
    knetsentry::agent::Lifecycle lifecycle;
    knetsentry::agent::Collector* module = journal.get();
    if (fim) { module = fim.get(); }
    const std::array<knetsentry::agent::Collector*, 1> modules{module};
    if (!lifecycle.start(module != nullptr ? std::span<knetsentry::agent::Collector* const>(modules) :
                                   std::span<knetsentry::agent::Collector* const>{})) {
        if (journal) { std::cerr << "knetsentry-agent: journal rejected: " << journal->error() << '\n'; }
        if (fim) { std::cerr << "knetsentry-agent: fim rejected: unsafe or unavailable baseline\n"; }
        return 1;
    }
    if (fim) {
        std::cout << "knetsentry-agent: ready; collectors=1; fim=local; monitoring=unavailable; network=disabled\n" << std::flush;
    } else if (journal) {
        std::cout << (mode == knetsentry::agent::JournalMode::Audit ?
            "knetsentry-agent: ready; collectors=1; journal=local-audit; monitoring=unavailable; network=disabled\n" :
            mode == knetsentry::agent::JournalMode::Authentication ?
            "knetsentry-agent: ready; collectors=1; journal=local-authentication; monitoring=unavailable; network=disabled\n" :
            "knetsentry-agent: ready; collectors=1; journal=local-metadata; monitoring=unavailable; network=disabled\n") << std::flush;
    } else {
        std::cout << "knetsentry-agent: ready; collectors=0; monitoring=unavailable; network=disabled\n" << std::flush;
    }
    if (!std::cout) { return 1; }
    if (journal) {
        bool audit_visibility_reported = false;
        bool buffer_status_reported = false;
        if (!binding.empty()) {
            std::cout << "knetsentry-agent: local telemetry buffering enabled; delivery=unavailable\n" << std::flush;
        }
        for (;;) {
            const auto previous = journal->count();
            if (!journal->pump()) {
                if (binding.empty() || !journal->collection_blocked()) {
                    std::cerr << "knetsentry-agent: journal rejected: " << journal->error() << '\n';
                    return 1;
                }
                if (!buffer_status_reported) {
                    std::cout << "knetsentry-agent: buffered collection blocked; coverage=unknown\n" << std::flush;
                    buffer_status_reported = true;
                }
            } else if (journal->backpressured() && !buffer_status_reported) {
                std::cout << "knetsentry-agent: telemetry buffer full; collection paused\n" << std::flush;
                buffer_status_reported = true;
            }
            if (mode == knetsentry::agent::JournalMode::Audit && !audit_visibility_reported) {
                std::cout << (journal->count() > previous ?
                    "knetsentry-agent: audit records observed; coverage=unknown\n" :
                    "knetsentry-agent: no new readable audit records; coverage=unknown\n") << std::flush;
                if (!std::cout) { return 1; }
                audit_visibility_reported = true;
            } else if (mode == knetsentry::agent::JournalMode::Audit && journal->count() > previous) {
                // Fixed diagnostic; never print record content or identifiers.
                std::cout << "knetsentry-agent: audit records observed; coverage=unknown\n" << std::flush;
                if (!std::cout) { return 1; }
            }
            const timespec delay{1, 0};
            const int signal = ::sigtimedwait(&signals, nullptr, &delay);
            if (signal == SIGINT || signal == SIGTERM) { break; }
            if (signal < 0 && (errno == EAGAIN || errno == EINTR)) { continue; }
            return 1;
        }
    } else if (fim) {
        for (;;) {
            const timespec delay{1, 0};
            const int signal = ::sigtimedwait(&signals, nullptr, &delay);
            if (signal == SIGINT || signal == SIGTERM) { break; }
            if (signal >= 0 || (errno != EAGAIN && errno != EINTR)) { return 1; }
            if (errno == EINTR) { continue; }
            std::array<knetsentry::agent::IntegrityChange, knetsentry::agent::max_fim_paths> changes{};
            if (!fim->pump(changes)) {
                std::cerr << "knetsentry-agent: fim rejected: unsafe or unstable observation; coverage=unknown\n";
                return 1;
            }
            for (std::size_t i = 0; i < changes.size(); ++i) {
                if (changes[i] != knetsentry::agent::IntegrityChange::None) {
                    std::cout << "knetsentry-agent: fim change; slot=" << i + 1 << "; kind="
                              << knetsentry::agent::change_name(changes[i]) << '\n' << std::flush;
                }
            }
            if (!std::cout) { return 1; }
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
        std::cout << "Usage: knetsentry-agent --run --schema-version 1 --collectors none\n       knetsentry-agent --run --schema-version 1 --collectors journal --unit NAME.service --state-dir /absolute/private/directory\n       knetsentry-agent --run --schema-version 1 --collectors authentication --unit NAME.service --state-dir /absolute/private/directory\n       knetsentry-agent --run --schema-version 1 --collectors audit --state-dir /absolute/private/directory\n       Append --buffer-for ENDPOINT32_MANAGER64 to a journal, authentication or audit configuration for offline buffering only\n       knetsentry-agent --run --schema-version 1 --collectors fim --path /absolute/file [--path /absolute/file ...]\n";
        return 0;
    }
    if (argc >= 6 && std::string_view(argv[5]) == "fim") {
        try {
            std::vector<std::string> paths;
            if (argc >= 8 && argc <= 22 && argc % 2 == 0 &&
                std::string_view(argv[1]) == "--run" && std::string_view(argv[2]) == "--schema-version" &&
                std::string_view(argv[3]) == "1" && std::string_view(argv[4]) == "--collectors") {
                for (int i = 6; i < argc; i += 2) {
                    const std::string_view path(argv[i + 1]);
                    if (std::string_view(argv[i]) != "--path" || !knetsentry::agent::valid_fim_path(path) ||
                        std::find(paths.begin(), paths.end(), path) != paths.end()) {
                        paths.clear();
                        break;
                    }
                    paths.emplace_back(path);
                }
                if (!paths.empty()) { return run({}, {}, knetsentry::agent::JournalMode::Metadata, {}, std::move(paths)); }
            }
            std::cerr << "knetsentry-agent: configuration rejected\n";
            return 2;
        } catch (...) { std::cerr << "knetsentry-agent: fim startup failed\n"; return 1; }
    }
    std::string_view binding;
    if ((argc == 10 || argc == 12) && std::string_view(argv[argc - 2]) == "--buffer-for") {
        binding = argv[argc - 1];
        if (!knetsentry::agent::valid_delivery_binding(binding)) {
            std::cerr << "knetsentry-agent: configuration rejected\n";
            return 2;
        }
        argc -= 2;
    }
    if (argc == 8 && std::string_view(argv[1]) == "--run" &&
        std::string_view(argv[2]) == "--schema-version" && std::string_view(argv[3]) == "1" &&
        std::string_view(argv[4]) == "--collectors" && std::string_view(argv[5]) == "audit" &&
        std::string_view(argv[6]) == "--state-dir" && knetsentry::agent::valid_journal_directory(argv[7])) {
        try { return run("audit", argv[7], knetsentry::agent::JournalMode::Audit, binding); }
        catch (...) { std::cerr << "knetsentry-agent: journal startup failed\n"; return 1; }
    }
    if (argc == 10 && std::string_view(argv[1]) == "--run" &&
        std::string_view(argv[2]) == "--schema-version" && std::string_view(argv[3]) == "1" &&
        std::string_view(argv[4]) == "--collectors" && (std::string_view(argv[5]) == "journal" ||
         (std::string_view(argv[5]) == "authentication" && knetsentry::agent::valid_auth_unit(argv[7]))) &&
        std::string_view(argv[6]) == "--unit" && std::string_view(argv[8]) == "--state-dir" &&
        knetsentry::agent::valid_journal_unit(argv[7]) && knetsentry::agent::valid_journal_directory(argv[9])) {
        try { return run(argv[7], argv[9], std::string_view(argv[5]) == "authentication" ?
            knetsentry::agent::JournalMode::Authentication : knetsentry::agent::JournalMode::Metadata, binding); }
        catch (...) { std::cerr << "knetsentry-agent: journal startup failed\n"; return 1; }
    }
    if (!binding.empty() || argc != 6 || std::string_view(argv[1]) != "--run") {
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

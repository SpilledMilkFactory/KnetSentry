// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/lifecycle.hpp"
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
[[nodiscard]] bool restrict_privileges() noexcept {
    uid_t real{}, effective{}, saved{};
    gid_t group{}, effective_group{}, saved_group{};
    if (::getresuid(&real, &effective, &saved) != 0 ||
        ::getresgid(&group, &effective_group, &saved_group) != 0 ||
        real == 0 || effective != real || saved != real ||
        group == 0 || effective_group != group || saved_group != group) {
        return false;
    }
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    std::array<__user_cap_data_struct, _LINUX_CAPABILITY_U32S_3> data{};
    if (::syscall(SYS_capget, &header, data.data()) != 0) { return false; }
    for (const auto& word : data) {
        if (word.effective != 0 || word.permitted != 0 || word.inheritable != 0) {
            return false;
        }
    }
    return ::prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) == 0 &&
        ::prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) == 1;
}
int run() {
    if (!restrict_privileges()) {
        std::cerr << "knetsentry-agent: privilege policy rejected\n";
        return 3;
    }
    ::umask(0077);
    sigset_t signals{};
    if (::sigemptyset(&signals) != 0 || ::sigaddset(&signals, SIGTERM) != 0 ||
        ::sigaddset(&signals, SIGINT) != 0 || ::sigprocmask(SIG_BLOCK, &signals, nullptr) != 0) {
        std::cerr << "knetsentry-agent: signal setup failed\n";
        return 1;
    }
    knetsentry::agent::Lifecycle lifecycle;
    if (!lifecycle.start({})) { return 1; }
    std::cout << "knetsentry-agent: ready; collectors=0; monitoring=unavailable; network=disabled\n" << std::flush;
    if (!std::cout) { return 1; }
    int signal{};
    if (::sigwait(&signals, &signal) != 0) { return 1; }
    lifecycle.stop();
    std::cout << "knetsentry-agent: stopped\n" << std::flush;
    return std::cout ? 0 : 1;
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "Usage: knetsentry-agent --run --schema-version 1 --collectors none\n";
        return 0;
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

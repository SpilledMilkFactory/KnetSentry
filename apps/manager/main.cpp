// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/build_info.hpp"
#include "knetsentry/core/diagnostics.hpp"
#include "knetsentry/service/lifecycle.hpp"

#include <csignal>
#include <iostream>
#include <pthread.h>
#include <string_view>
#include <unistd.h>

namespace {
using knetsentry::core::DiagnosticComponent;
using knetsentry::core::DiagnosticEvent;
using knetsentry::core::DiagnosticLevel;
using knetsentry::core::DiagnosticLogger;
using knetsentry::core::DiagnosticOutcome;
using knetsentry::core::DiagnosticRecord;
using knetsentry::service::Lifecycle;

[[nodiscard]] bool publish(DiagnosticLogger& logger, DiagnosticLevel level,
                           DiagnosticEvent event, DiagnosticOutcome outcome) noexcept {
    return logger.write(DiagnosticRecord{
        .level = level,
        .component = DiagnosticComponent::Manager,
        .event = event,
        .outcome = outcome,
    });
}

[[nodiscard]] int run() {
    // A management service must never accidentally inherit root authority.
    if (geteuid() == 0) {
        std::cerr << "knetsentryd: root execution prohibited\n";
        return 3;
    }
    DiagnosticLogger logger(std::cerr);
    Lifecycle lifecycle;

    // The blocking signal mask is installed before reporting readiness.
    // sigwait synchronously consumes SIGTERM/SIGINT; no signal handler calls
    // C++ code, allocates, or touches streams. No threads are spawned here.
    sigset_t stop_signals{};
    if (sigemptyset(&stop_signals) != 0 ||
        sigaddset(&stop_signals, SIGINT) != 0 ||
        sigaddset(&stop_signals, SIGTERM) != 0 ||
        pthread_sigmask(SIG_BLOCK, &stop_signals, nullptr) != 0) {
        static_cast<void>(lifecycle.mark_failed());
        static_cast<void>(publish(logger, DiagnosticLevel::Error,
            DiagnosticEvent::ManagerFailed, DiagnosticOutcome::Failure));
        return 1;
    }

    if (!lifecycle.begin_start() ||
        !publish(logger, DiagnosticLevel::Info, DiagnosticEvent::ManagerStarting,
                 DiagnosticOutcome::Started)) {
        static_cast<void>(lifecycle.mark_failed());
        return 1;
    }

    // M2.1 has no listeners, sockets, filesystem state, privileges, or worker
    // dependencies to initialize. "ready" means only lifecycle availability.
    if (!lifecycle.mark_ready() ||
        !publish(logger, DiagnosticLevel::Info, DiagnosticEvent::ManagerReady,
                 DiagnosticOutcome::Success)) {
        static_cast<void>(lifecycle.mark_failed());
        static_cast<void>(publish(logger, DiagnosticLevel::Error,
            DiagnosticEvent::ManagerFailed, DiagnosticOutcome::Failure));
        return 1;
    }

    int received = 0;
    if (sigwait(&stop_signals, &received) != 0 ||
        (received != SIGINT && received != SIGTERM)) {
        static_cast<void>(lifecycle.mark_failed());
        static_cast<void>(publish(logger, DiagnosticLevel::Error,
            DiagnosticEvent::ManagerFailed, DiagnosticOutcome::Failure));
        return 1;
    }
    if (!lifecycle.request_stop() ||
        !publish(logger, DiagnosticLevel::Info, DiagnosticEvent::ManagerStopping,
                 DiagnosticOutcome::Started)) {
        static_cast<void>(lifecycle.mark_failed());
        return 1;
    }
    if (!lifecycle.complete_stop() ||
        !publish(logger, DiagnosticLevel::Info, DiagnosticEvent::ManagerStopped,
                 DiagnosticOutcome::Success)) {
        static_cast<void>(lifecycle.mark_failed());
        return 1;
    }
    return 0;
}
} // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "KnetSentry manager " << knetsentry::core::project_version() << '\n';
        return 0;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "Usage: knetsentryd [--help|--version]\n"
                     "Foreground-only, unprivileged lifecycle foundation.\n"
                     "Stop with SIGTERM or SIGINT; no monitoring or listeners.\n";
        return 0;
    }
    if (argc != 1) {
        std::cerr << "knetsentryd: unsupported argument (see --help)\n";
        return 2;
    }
    return run();
}

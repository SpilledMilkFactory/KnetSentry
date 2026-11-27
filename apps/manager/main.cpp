// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/build_info.hpp"
#include "knetsentry/core/diagnostics.hpp"
#include "knetsentry/service/lifecycle.hpp"
#include "knetsentry/service/configuration.hpp"
#include "knetsentry/service/local_ipc.hpp"
#include "knetsentry/service/audit.hpp"
#include <knetsentry/storage/sqlite_event_store.hpp>
#include <memory>

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
using knetsentry::service::AuditEvent;
using knetsentry::service::AuditLog;

[[nodiscard]] bool publish(DiagnosticLogger& logger, DiagnosticLevel level,
                           DiagnosticEvent event, DiagnosticOutcome outcome) noexcept {
    return logger.write(DiagnosticRecord{
        .level = level,
        .component = DiagnosticComponent::Manager,
        .event = event,
        .outcome = outcome,
    });
}

[[nodiscard]] int run(std::string_view configuration_path, std::string_view ipc_dir = {},
                      std::string_view audit_dir = {}, std::string_view enrollment_dir = {},
                      std::string_view event_dir = {}, std::string_view alert_dir = {},
                      std::string_view alert_access = {}) {
    // A management service must never accidentally inherit root authority.
    if (geteuid() == 0) {
        std::cerr << "knetsentryd: root execution prohibited\n";
        return 3;
    }
    if (!event_dir.empty() && (ipc_dir.empty() || audit_dir.empty() || event_dir == ipc_dir || event_dir == audit_dir || event_dir == enrollment_dir)) {
        std::cerr << "knetsentryd: event inspection requires separate private storage, IPC and persistent audit directories\n"; return 2;
    }
    if ((!alert_dir.empty() || !alert_access.empty()) &&
        (alert_dir.empty() || event_dir.empty() || alert_dir == event_dir || alert_dir == ipc_dir ||
         alert_dir == audit_dir || alert_dir == enrollment_dir || (alert_access != "read" && alert_access != "ack"))) {
        std::cerr << "knetsentryd: alert inspection requires explicit separate state and access policy\n"; return 2;
    }
    DiagnosticLogger logger(std::cerr);
    Lifecycle lifecycle;
    AuditLog audit;
    const auto audit_failure = [&]() {
        static_cast<void>(lifecycle.mark_failed());
        std::cerr << "knetsentryd: audit unavailable or incomplete (no fallback)\n";
        return 6;
    };
    if (!audit_dir.empty()) {
        // A file-size limit must become a reported write error, not an
        // unhandled SIGXFSZ that silently terminates the audit owner.
        struct sigaction file_limit{};
        file_limit.sa_handler = SIG_IGN;
        if (sigemptyset(&file_limit.sa_mask) != 0 ||
            sigaction(SIGXFSZ, &file_limit, nullptr) != 0 ||
            !audit.open(audit_dir)) { return audit_failure(); }
    }
    const auto fail = [&](int status) {
        return audit.record(AuditEvent::Failed) ? status : audit_failure();
    };
    knetsentry::service::HealthTracker health(!configuration_path.empty());

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
        return fail(1);
    }

    if (!audit.record(AuditEvent::Starting)) { return audit_failure(); }
    if (!lifecycle.begin_start() ||
        !publish(logger, DiagnosticLevel::Info, DiagnosticEvent::ManagerStarting,
                 DiagnosticOutcome::Started)) {
        static_cast<void>(lifecycle.mark_failed());
        return fail(1);
    }

    // M2.2: if the operator supplied a file it is mandatory and must pass
    // complete validation. Never replace a rejected file with safe defaults.
    // The built-in defaults apply ONLY when no configuration was supplied.
    if (!configuration_path.empty() &&
        !knetsentry::service::load_configuration(configuration_path).ok()) {
        static_cast<void>(lifecycle.mark_failed());
        static_cast<void>(publish(logger, DiagnosticLevel::Error,
            DiagnosticEvent::ManagerFailed, DiagnosticOutcome::Rejected));
        std::cerr << "knetsentryd: configuration rejected (no fallback)\n";
        if (!audit.record(AuditEvent::ConfigRejected)) { return audit_failure(); }
        return fail(4);
    }
    if (!audit.record(configuration_path.empty() ? AuditEvent::ConfigDefault :
                      AuditEvent::ConfigValidated)) { return audit_failure(); }

    // M2.3: local socket is strictly opt-in; bind and validate BEFORE ready.
    // Invalid directories, existing socket entries, and bind errors deny startup.
    std::unique_ptr<knetsentry::storage::SqliteEventStore> event_store;
    knetsentry::service::LocalIpcServer ipc;
    if (!event_dir.empty()) {
        try {
            using namespace knetsentry::storage;
            event_store = std::make_unique<SqliteEventStore>(std::string(event_dir), LegacyIntegrityPolicy::Reject, StoragePolicy{}, StorageOpenMode::ExistingV4);
            if (!ipc.set_event_store(*event_store)) { return fail(1); }
        } catch (...) { std::cerr << "knetsentryd: event store unavailable (no fallback)\n"; return fail(1); }
    }
    if (!alert_dir.empty()) {
        try {
            auto policy = knetsentry::service::load_alert_profile(alert_dir);
            if (!policy || !ipc.set_alert_scope(std::move(*policy),alert_dir,alert_access == "ack")) { return fail(1); }
        } catch (...) { return fail(1); }
    }
    if (!ipc_dir.empty() && !ipc.open(ipc_dir, stop_signals)) {
        static_cast<void>(lifecycle.mark_failed());
        static_cast<void>(publish(logger, DiagnosticLevel::Error,
            DiagnosticEvent::ManagerFailed, DiagnosticOutcome::Rejected));
        std::cerr << "knetsentryd: local IPC unavailable (no fallback)\n";
        if (!audit.record(AuditEvent::IpcRejected)) { return audit_failure(); }
        return fail(5);
    }

    if (!enrollment_dir.empty() && (ipc_dir.empty() || !ipc.set_enrollment_directory(enrollment_dir))) {
        static_cast<void>(lifecycle.mark_failed());
        std::cerr << "knetsentryd: enrollment directory rejected (no fallback)\n";
        return fail(5);
    }
    if (!ipc_dir.empty() && !audit.record(AuditEvent::IpcReady)) { return audit_failure(); }

    // Readiness means lifecycle operation and optional local IPC only; there
    // is no monitoring, database, remote listener or privileged authority.
    if (!lifecycle.mark_ready()) { return fail(1); }
    if (!audit.record(AuditEvent::Ready)) { return audit_failure(); }
    if (!publish(logger, DiagnosticLevel::Info, DiagnosticEvent::ManagerReady,
                 DiagnosticOutcome::Success)) {
        static_cast<void>(lifecycle.mark_failed());
        static_cast<void>(publish(logger, DiagnosticLevel::Error,
            DiagnosticEvent::ManagerFailed, DiagnosticOutcome::Failure));
        return fail(1);
    }

    int received = 0;
    const bool completed = ipc_dir.empty()
        ? (sigwait(&stop_signals, &received) == 0 &&
           (received == SIGINT || received == SIGTERM))
        : ipc.serve(lifecycle, health, audit);
    if (!audit.ok()) { return audit_failure(); }
    if (!completed) {
        static_cast<void>(lifecycle.mark_failed());
        static_cast<void>(publish(logger, DiagnosticLevel::Error,
            DiagnosticEvent::ManagerFailed, DiagnosticOutcome::Failure));
        return fail(1);
    }
    if (!lifecycle.request_stop()) { return fail(1); }
    if (!audit.record(AuditEvent::Stopping)) { return audit_failure(); }
    if (!publish(logger, DiagnosticLevel::Info, DiagnosticEvent::ManagerStopping,
                 DiagnosticOutcome::Started)) {
        static_cast<void>(lifecycle.mark_failed());
        return fail(1);
    }
    if (!lifecycle.complete_stop()) { return fail(1); }
    if (!audit.record(AuditEvent::Stopped)) { return audit_failure(); }
    if (!publish(logger, DiagnosticLevel::Info, DiagnosticEvent::ManagerStopped,
                 DiagnosticOutcome::Success)) {
        static_cast<void>(lifecycle.mark_failed());
        return fail(1);
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
        std::cout << "Usage: knetsentryd [--help|--version|--config ABS_PATH|--check-config ABS_PATH|--ipc-dir ABS_DIR|--audit-dir ABS_DIR|--enrollment-dir ABS_DIR|--event-store-dir ABS_DIR|--alert-dir ABS_DIR|--alert-access read|ack]\n"
                     "Run options may be combined once each; audit requires a fresh private directory.\n"
                     "Foreground-only, unprivileged lifecycle foundation.\n"
                     "Stop with SIGTERM or SIGINT; no monitoring or remote listeners.\n";
        return 0;
    }
    if (argc == 3 && std::string_view(argv[1]) == "--check-config") {
        if (!knetsentry::service::load_configuration(argv[2]).ok()) {
            std::cerr << "knetsentryd: configuration rejected (no fallback)\n";
            return 4;
        }
        std::cout << "KnetSentry configuration schema v1: valid (lifecycle only)\n";
        return 0;
    }
    std::string_view config_path;
    std::string_view ipc_dir;
    std::string_view audit_dir;
    std::string_view enrollment_dir;
    std::string_view event_dir;
    std::string_view alert_dir, alert_access;
    if (argc <= 15 && argc % 2 == 1) {
        bool valid = true;
        for (int i = 1; i < argc; i += 2) {
            const std::string_view option(argv[i]);
            const std::string_view value(argv[i + 1]);
            if (value.empty()) { valid = false; break; }
            if (option == "--config" && config_path.empty()) { config_path = value; }
            else if (option == "--ipc-dir" && ipc_dir.empty()) { ipc_dir = value; }
            else if (option == "--audit-dir" && audit_dir.empty()) { audit_dir = value; }
            else if (option == "--enrollment-dir" && enrollment_dir.empty()) { enrollment_dir = value; }
            else if (option == "--event-store-dir" && event_dir.empty()) { event_dir = value; }
            else if (option == "--alert-dir" && alert_dir.empty()) { alert_dir = value; }
            else if (option == "--alert-access" && alert_access.empty()) { alert_access = value; }
            else { valid = false; break; }
        }
        if (valid) { return run(config_path, ipc_dir, audit_dir, enrollment_dir, event_dir, alert_dir, alert_access); }
    }
    std::cerr << "knetsentryd: unsupported argument (see --help)\n";
    return 2;
}

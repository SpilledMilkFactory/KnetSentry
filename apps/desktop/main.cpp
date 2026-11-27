// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/build_info.hpp"
#include "service_health_model.hpp"
#include "event_explorer_model.hpp"
#include "alert_model.hpp"
#include "daemon_control.hpp"
#include "knetsentry/core/diagnostics.hpp"

#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDir>
#include <QMetaObject>
#include <unistd.h>
#include <QGuiApplication>
#include <QEventLoop>
#include <QQmlEngine>
#include <QTimer>
#include <QQmlApplicationEngine>
#include <QQuickWindow>
#include <QString>
#include <QStringList>
#include <QVariant>

#include <iostream>
#include <string_view>

namespace {
void set_application_metadata() {
    QCoreApplication::setApplicationName(QStringLiteral("KnetSentry"));
    QCoreApplication::setApplicationVersion(
        QString::fromUtf8(knetsentry::core::project_version().data(),
                          static_cast<qsizetype>(knetsentry::core::project_version().size())));
    QCoreApplication::setOrganizationName(QStringLiteral("SpilledMilkFactory"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("github.com/SpilledMilkFactory"));
}

void configure_parser(QCommandLineParser &parser) {
    parser.setApplicationDescription(QStringLiteral(
        "KnetSentry network scope, enrollment, stored event and alert inspection, and local manager health; no SIEM monitoring is active."));
    parser.addHelpOption();
    parser.addOption(QCommandLineOption(QStringLiteral("agent-status-stdin"),
        QStringLiteral("Read aggregate local agent status from an explicitly inherited pipe on stdin.")));
    parser.addVersionOption();
    parser.addOption(QCommandLineOption(QStringLiteral("ipc-dir"),
        QStringLiteral("Explicit private manager IPC directory for health, enrollment, opted-in event and alert inspection and acknowledgement."),
        QStringLiteral("absolute-directory")));
}

// Exercise the actual rendered Settings cards, not a detached model alone.
// Expected values are independent of the model getters to detect misleading
// zero counts or stale connected state after a failed health exchange.
bool scope_page_matches(const QObject& root, bool connected, bool rejected = false,
                        bool validated = false) {
    if (root.property("activeSection").toString() != QStringLiteral("settings") ||
        !root.property("currentPageScopeVisible").toBool()) { return false; }
    const auto state = root.property("currentPageScopeState").toString();
    const auto networks = root.property("currentPageScopeNetworks").toString();
    const auto interfaces = root.property("currentPageScopeInterfaces").toString();
    const auto denials = root.property("currentPageScopeDenials").toString();
    if (!connected) {
        return state == QStringLiteral("Unavailable — no current verified daemon health") &&
            networks == QStringLiteral("Unavailable — approved network inventory not reported.") &&
            interfaces == QStringLiteral("Unavailable — approved interface inventory not reported.") &&
            denials == QStringLiteral("Network connection denials: unavailable (not collected).\n"
                                      "Local IPC rejected requests: unavailable.");
    }
    return state == (validated
        ? QStringLiteral("Lifecycle only — network authorization not activated.\n"
                         "Configuration: Validated v1 file. Policy revision and firewall state are not reported.")
        : QStringLiteral("Lifecycle only — network authorization not activated.\n"
                         "Configuration: Safe defaults. Policy revision and firewall state are not reported.")) &&
        networks == QStringLiteral("No operational approvals loaded by the lifecycle-only manager. No network inventory is published.") &&
        interfaces == QStringLiteral("No operational interface bindings loaded. Local adapters are not automatically approved.") &&
        denials == (rejected
            ? QStringLiteral("Network connection denials: unavailable (not collected).\n"
                             "Local IPC rejected requests: 1 (not network denials or incidents).")
            : QStringLiteral("Network connection denials: unavailable (not collected).\n"
                             "Local IPC rejected requests: 0 (not network denials or incidents)."));
}

bool requests_text_only(int argc, char *argv[]) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view argument(argv[i]);
        if (argument == "--help" || argument == "-h" || argument == "--version" ||
            argument == "-v") {
            return true;
        }
    }
    return false;
}
} // namespace

int main(int argc, char *argv[]) {
    // Informational commands must work in headless consoles and on hosts
    // without a working Wayland/X11 display. Do not construct QGuiApplication.
    if (requests_text_only(argc, argv)) {
        QCoreApplication app(argc, argv);
        set_application_metadata();
        QCommandLineParser parser;
        configure_parser(parser);
        parser.process(app);
        return 0;
    }

    QGuiApplication app(argc, argv);
    set_application_metadata();
    QGuiApplication::setDesktopFileName(
        QStringLiteral("io.github.spilledmilkfactory.KnetSentry"));

    // Fixed-code structured diagnostics. Never pass QML errors, CLI strings,
    // credentials or framework messages to this privacy-safe publisher.
    knetsentry::core::DiagnosticLogger diagnostics(std::clog);
    auto publish = [&diagnostics](knetsentry::core::DiagnosticLevel level,
                                  knetsentry::core::DiagnosticEvent event,
                                  knetsentry::core::DiagnosticOutcome outcome) {
        if (!diagnostics.write({level, knetsentry::core::DiagnosticComponent::Desktop,
                                event, outcome})) {
            std::cerr << "KnetSentry: diagnostic sink unavailable.\n";
        }
    };
    publish(knetsentry::core::DiagnosticLevel::Info,
            knetsentry::core::DiagnosticEvent::GuiStarting,
            knetsentry::core::DiagnosticOutcome::Started);

    QCommandLineParser parser;
    configure_parser(parser);
    const QCommandLineOption qml_smoke_test(
        QStringLiteral("self-test-qml"),
        QStringLiteral("Load the embedded Kirigami window and exit; intended for tests."));
    const QCommandLineOption navigation_smoke_test(
        QStringLiteral("self-test-navigation"),
        QStringLiteral("Exercise all seven non-operational navigation pages and exit."));
    parser.addOption(qml_smoke_test);
    parser.addOption(navigation_smoke_test);
    const QCommandLineOption visual_smoke_test(
        QStringLiteral("self-test-visual"),
        QStringLiteral("Verify the embedded visual design tokens and QML pages."));
    parser.addOption(visual_smoke_test);
    const QCommandLineOption health_smoke_test(
        QStringLiteral("self-test-health"),
        QStringLiteral("Bounded live health/disconnect/reconnect integration test."));
    parser.addOption(health_smoke_test);
    const QCommandLineOption control_smoke_test(QStringLiteral("self-test-daemon-controls"),
        QStringLiteral("Exercise toolbar controls against a private foreground manager."));
    parser.addOption(control_smoke_test);
    const QCommandLineOption telemetry_smoke_test(QStringLiteral("self-test-telemetry"),
        QStringLiteral("Verify rendered local status and disconnect using a synthetic test pipe."));
    parser.addOption(telemetry_smoke_test);
    const QCommandLineOption events_smoke_test(QStringLiteral("self-test-events"),
        QStringLiteral("Verify rendered event explorer against the private M6.8 synthetic store."));
    parser.addOption(events_smoke_test);
    const QCommandLineOption alerts_smoke_test(QStringLiteral("self-test-alerts"),
        QStringLiteral("Verify rendered alert interface against a disposable M7.7 synthetic ledger."));
    parser.addOption(alerts_smoke_test);
    parser.process(app);

    // The model outlives QML and is not a management authority.
    knetsentry::desktop::ServiceHealthModel health(parser.value(QStringLiteral("ipc-dir")));
    if (parser.isSet(QStringLiteral("agent-status-stdin")) && !health.attachTelemetry(STDIN_FILENO)) {
        std::cerr << "KnetSentry: local status pipe rejected.\n";
        return 2;
    }
    knetsentry::desktop::DaemonControl control(health, parser.isSet(QStringLiteral("ipc-dir")),
        QDir::cleanPath(QCoreApplication::applicationDirPath() + QStringLiteral("/../manager/knetsentryd")));
    knetsentry::desktop::EventExplorerModel events(parser.value(QStringLiteral("ipc-dir")));
    knetsentry::desktop::AlertModel alerts(parser.value(QStringLiteral("ipc-dir")));
    QQmlApplicationEngine engine;
    QQmlEngine::setObjectOwnership(&alerts, QQmlEngine::CppOwnership);
    QQmlEngine::setObjectOwnership(&events, QQmlEngine::CppOwnership);
    QQmlEngine::setObjectOwnership(&health, QQmlEngine::CppOwnership);
    QQmlEngine::setObjectOwnership(&control, QQmlEngine::CppOwnership);
    engine.setInitialProperties({{QStringLiteral("alertModel"), QVariant::fromValue(&alerts)},
                                 {QStringLiteral("eventModel"), QVariant::fromValue(&events)},
                                 {QStringLiteral("healthModel"), QVariant::fromValue(&health)},
                                 {QStringLiteral("daemonControl"), QVariant::fromValue(&control)}});
    engine.loadFromModule("io.github.spilledmilkfactory.KnetSentry", "Main");
    if (engine.rootObjects().size() != 1) {
        publish(knetsentry::core::DiagnosticLevel::Error,
                knetsentry::core::DiagnosticEvent::GuiLoadRejected,
                knetsentry::core::DiagnosticOutcome::Failure);
        std::cerr << "KnetSentry: failed to instantiate the QML root window.\n";
        return 1;
    }
    auto *window = qobject_cast<QQuickWindow *>(engine.rootObjects().constFirst());
    if (window == nullptr || window->objectName() != QStringLiteral("knetSentryMainWindow")) {
        publish(knetsentry::core::DiagnosticLevel::Error,
                knetsentry::core::DiagnosticEvent::GuiLoadRejected,
                knetsentry::core::DiagnosticOutcome::Rejected);
        std::cerr << "KnetSentry: unexpected QML root; Kirigami startup not qualified.\n";
        return 1;
    }
    publish(knetsentry::core::DiagnosticLevel::Info,
            knetsentry::core::DiagnosticEvent::GuiReady,
            knetsentry::core::DiagnosticOutcome::Success);
    if (parser.isSet(qml_smoke_test)) {
        std::cout << "KnetSentry M1.3 Kirigami QML smoke: PASS (not an operational SIEM)\n";
        return 0;
    }
    if (parser.isSet(visual_smoke_test)) {
        QObject *root = engine.rootObjects().constFirst();
        if (root->property("visualSystemVersion").toString() != QStringLiteral("M1.5") ||
            !root->property("visualTokensValid").toBool() ||
            root->property("currentPageVisualSystem").toString() != QStringLiteral("M1.5")) {
            std::cerr << "KnetSentry: visual token contract failed.\n";
            return 1;
        }
        if (!root->setProperty("navigationRequest", QStringLiteral("settings"))) {
            std::cerr << "KnetSentry: settings page could not be selected.\n";
            return 1;
        }
        QCoreApplication::processEvents();
        if (root->property("activeSection").toString() != QStringLiteral("settings") ||
            root->property("currentPageVisualSystem").toString() != QStringLiteral("M1.5")) {
            std::cerr << "KnetSentry: visual system not active on settings page.\n";
            return 1;
        }
        std::cout << "KnetSentry M1.5 visual system: PASS (platform palette; no telemetry)\n";
        return 0;
    }
    if (parser.isSet(navigation_smoke_test)) {
        const QStringList sections = {
            QStringLiteral("dashboard"), QStringLiteral("assets"),
            QStringLiteral("events"), QStringLiteral("detections"),
            QStringLiteral("alerts"), QStringLiteral("investigations"),
            QStringLiteral("settings")};
        // Exercise repeated replacement, not just one pass, to expose
        // stale-page ownership and transient scene-attachment failures.
        for (int pass = 0; pass < 4; ++pass) {
            for (const QString &section : sections) {
                if (!engine.rootObjects().constFirst()->setProperty("navigationRequest", section)) {
                    std::cerr << "KnetSentry: navigation request property is unavailable.\n";
                    return 1;
                }
                QCoreApplication::processEvents();
                const QObject *root = engine.rootObjects().constFirst();
                if (root->property("activeSection").toString() != section ||
                    root->property("currentPageSection").toString() != section ||
                    root->property("navigationDepth").toInt() != 1 ||
                    root->property("currentPageAgentRosterVisible").toBool() != (section == QStringLiteral("assets")) ||
                    (section == QStringLiteral("assets") &&
                     (!root->property("currentPageAgentRegistry").toString().startsWith(QStringLiteral("Unavailable")) ||
                      !root->property("currentPageApprovedAgents").toString().startsWith(QStringLiteral("Unavailable")) ||
                      !root->property("currentPageRevokedAgents").toString().startsWith(QStringLiteral("Unavailable")))) ||
                    root->property("currentPageTelemetryVisible").toBool() !=
                        (section == QStringLiteral("assets") || section == QStringLiteral("dashboard")) ||
                    ((section == QStringLiteral("assets") || section == QStringLiteral("dashboard")) &&
                     (!root->property("currentPageTelemetryStatus").toString().startsWith(QStringLiteral("Unavailable")) ||
                      root->property("currentPageTelemetryRate").toString() != QStringLiteral("Unavailable"))) ||
                    root->property("currentPageScopeVisible").toBool() != (section == QStringLiteral("settings")) ||
                    (section == QStringLiteral("settings") && !scope_page_matches(*root, false))) {
                    std::cerr << "KnetSentry: failed navigation or unbounded page stack.\n";
                    return 1;
                }
            }
        }
        // Invalid destinations must never change the displayed page.
        if (!engine.rootObjects().constFirst()->setProperty(
                "navigationRequest", QStringLiteral("unapproved"))) {
            return 1;
        }
        QCoreApplication::processEvents();
        const QObject *root = engine.rootObjects().constFirst();
        if (root->property("activeSection").toString() != QStringLiteral("settings") ||
            root->property("currentPageSection").toString() != QStringLiteral("settings") ||
            root->property("navigationDepth").toInt() != 1) {
            std::cerr << "KnetSentry: invalid destination was not rejected.\n";
            return 1;
        }
        std::cout << "M3.8 Settings scope visibility and unavailable state: PASS\n";
        std::cout << "KnetSentry M1.4 primary navigation: PASS (7 sections; no telemetry)\n";
        return 0;
    }
    if (parser.isSet(events_smoke_test)) {
        if (!parser.isSet(QStringLiteral("ipc-dir"))) { return 1; }
        QObject* root = engine.rootObjects().constFirst();
        if (!root->setProperty("navigationRequest", QStringLiteral("events"))) { return 1; }
        QCoreApplication::processEvents();
        QObject* search_button = root->property("currentEventSearchButton").value<QObject*>();
        QObject* next_button = root->property("currentEventNextButton").value<QObject*>();
        if (!search_button || !next_button || !QMetaObject::invokeMethod(search_button, "clicked")) { return 1; }
        QEventLoop loop;
        QTimer check;
        QTimer deadline;
        deadline.setSingleShot(true);
        int stage = 0;
        QObject::connect(&deadline, &QTimer::timeout, &loop, [&loop] { loop.exit(1); });
        QObject::connect(&check, &QTimer::timeout, &loop, [&] {
            if (events.busy()) { return; }
            const auto count = root->property("currentEventCount").toInt();
            if (stage == 0) {
                if (count != 8 || !events.more() || !events.data(events.index(0, 0), Qt::DisplayRole).toString().startsWith(QStringLiteral("#1 ·"))) { loop.exit(1); return; }
                events.select(0);
                if (!root->property("currentEventDetail").toString().startsWith(QStringLiteral("Event ID: 1\n")) ||
                    !root->property("currentEventStatus").toString().contains(QStringLiteral("stored snapshot")) ||
                    !QMetaObject::invokeMethod(next_button, "clicked")) { loop.exit(1); return; }
                ++stage;
            } else if (stage == 1) {
                if (count != 8 || !events.more() || !events.detail().isEmpty() ||
                    !events.data(events.index(0, 0), Qt::DisplayRole).toString().startsWith(QStringLiteral("#9 ·"))) { loop.exit(1); return; }
                events.search(QStringLiteral("ssh.service"), 1, 2, true);
                ++stage;
            } else if (stage == 2) {
                if (count != 8 || !events.more() || !events.data(events.index(0, 0), Qt::DisplayRole).toString().startsWith(QStringLiteral("#20 ·"))) { loop.exit(1); return; }
                events.search(QStringLiteral("fixture.service"), -1, -1, false);
                ++stage;
            } else {
                if (count != 0 || events.more() || !root->property("currentEventStatus").toString().startsWith(QStringLiteral("No matching stored events")) ||
                    !root->setProperty("navigationRequest", QStringLiteral("dashboard")) || events.rowCount() != 0 || !events.detail().isEmpty()) { loop.exit(1); return; }
                std::cout << "M6.8 rendered event explorer: PASS\n";
                loop.exit(0);
            }
        });
        check.start(50); deadline.start(10000);
        return loop.exec();
    }
    if (parser.isSet(alerts_smoke_test)) {
        if (!parser.isSet(QStringLiteral("ipc-dir"))) { return 1; }
        QObject* root = engine.rootObjects().constFirst();
        if (!root->setProperty("navigationRequest", QStringLiteral("alerts"))) { return 1; }
        QCoreApplication::processEvents();
        QObject* refresh = root->property("currentAlertRefreshButton").value<QObject*>();
        QObject* ack = root->property("currentAlertAckButton").value<QObject*>();
        if (!refresh || !ack || !QMetaObject::invokeMethod(refresh,"clicked")) { return 1; }
        QEventLoop loop; QTimer check; QTimer deadline; deadline.setSingleShot(true); int stage = 0;
        QObject::connect(&deadline,&QTimer::timeout,&loop,[&loop] { loop.exit(1); });
        QObject::connect(&check,&QTimer::timeout,&loop,[&] {
            if (alerts.busy()) { return; }
            if (stage == 0) {
                if (root->property("currentAlertCount").toInt() != 8 || !alerts.more()) { loop.exit(1); return; }
                alerts.select(1); // First alert already acknowledged by the native IPC regression.
                if (!root->property("currentAlertDetail").toString().contains(QStringLiteral("Alert 1/3")) || !alerts.canAcknowledge()) { loop.exit(1); return; }
                alerts.inspectEvidence(0); ++stage;
            } else if (stage == 1) {
                if (!root->property("currentAlertEvidence").toString().contains(QStringLiteral("Verified stored evidence #2")) || !QMetaObject::invokeMethod(ack,"clicked")) { loop.exit(1); return; }
                ++stage;
            } else if (stage == 2) {
                if (!alerts.status().startsWith(QStringLiteral("Acknowledgement committed"))) { loop.exit(1); return; }
                alerts.search(3); ++stage;
            } else if (stage == 3) {
                alerts.select(1);
                if (alerts.rowCount() != 8 || alerts.canAcknowledge() || !alerts.detail().contains(QStringLiteral("Acknowledged"))) { loop.exit(1); return; }
                alerts.next(); ++stage;
            } else if (stage == 4) {
                if (alerts.rowCount() != 3 || alerts.more()) { loop.exit(1); return; }
                alerts.search(4); ++stage;
            } else {
                if (alerts.rowCount() != 0 || !alerts.status().startsWith(QStringLiteral("No matching")) || !root->setProperty("navigationRequest",QStringLiteral("dashboard")) || alerts.rowCount() != 0 || !alerts.detail().isEmpty()) { loop.exit(1); return; }
                std::cout << "M7.7 rendered alert interface: PASS\n"; loop.exit(0);
            }
        });
        check.start(50); deadline.start(12000); return loop.exec();
    }
    if (parser.isSet(telemetry_smoke_test)) {
        if (!parser.isSet(QStringLiteral("agent-status-stdin"))) { return 1; }
        QObject* root = engine.rootObjects().constFirst();
        QEventLoop loop;
        QTimer check;
        QTimer deadline;
        deadline.setSingleShot(true);
        int stage = 0;
        QObject::connect(&deadline, &QTimer::timeout, &loop, [&loop] { loop.exit(1); });
        QObject::connect(&check, &QTimer::timeout, &loop, [&] {
            if (stage < 2 && root->property("currentPageTelemetryStatus").toString().startsWith(QStringLiteral("Current local report"))) {
                if (!root->property("currentPageTelemetryVisible").toBool() ||
                    root->property("currentPageTelemetryCollector").toString() != QStringLiteral("Journal metadata") ||
                    root->property("currentPageTelemetryRate").toString() != QStringLiteral("2.00 observations/s (2 in 1000 ms)") ||
                    !root->property("currentPageTelemetryQueue").toString().startsWith(QStringLiteral("12 / 128"))) {
                    loop.exit(1); return;
                }
                if (stage == 0) {
                    if (root->property("currentPageSection").toString() != QStringLiteral("dashboard") ||
                        !root->setProperty("navigationRequest", QStringLiteral("assets"))) { loop.exit(1); return; }
                    stage = 1;
                } else {
                    if (root->property("currentPageSection").toString() != QStringLiteral("assets")) { loop.exit(1); return; }
                    stage = 2;
                    std::cout << "M5.9 rendered current aggregate: PASS\n" << std::flush;
                }
            } else if (stage == 2 && root->property("currentPageTelemetryStatus").toString().contains(QStringLiteral("disconnected"))) {
                if (root->property("currentPageTelemetryCollector").toString() != QStringLiteral("Unavailable") ||
                    root->property("currentPageTelemetryRate").toString() != QStringLiteral("Unavailable") ||
                    root->property("currentPageTelemetryQueue").toString() != QStringLiteral("Unavailable")) {
                    loop.exit(1); return;
                }
                std::cout << "M5.9 rendered disconnect clears measurements: PASS\n" << std::flush;
                loop.exit(0);
            }
        });
        check.start(50);
        deadline.start(10000);
        return loop.exec();
    }
    if (parser.isSet(control_smoke_test)) {
        if (::geteuid() == 0 || parser.isSet(QStringLiteral("ipc-dir"))) { return 1; }
        QObject* root = engine.rootObjects().constFirst();
        QObject* play = root->property("toolbarStartButton").value<QObject*>();
        QObject* stop = root->property("toolbarStopButton").value<QObject*>();
        if (play == nullptr || stop == nullptr || !play->property("enabled").toBool() ||
            stop->property("enabled").toBool()) { return 1; }
        QEventLoop loop;
        QTimer check;
        QTimer deadline;
        deadline.setSingleShot(true);
        QObject::connect(&deadline, &QTimer::timeout, &loop, [&loop] { loop.exit(1); });
        int stage = 0;
        QObject::connect(&check, &QTimer::timeout, &loop, [&] {
            if (root->property("toolbarTone").toInt() != control.tone() ||
                root->property("toolbarPulse").toBool() != control.pulse()) { loop.exit(1); return; }
            if ((stage == 0 || stage == 2) && control.tone() == 2 && control.pulse()) {
                if (!health.available() || play->property("enabled").toBool() ||
                    !stop->property("enabled").toBool()) { loop.exit(1); return; }
                if (!root->setProperty("navigationRequest", QStringLiteral("settings")) ||
                    root->property("activeSection").toString() != QStringLiteral("settings") ||
                    !QMetaObject::invokeMethod(stop, "clicked")) { loop.exit(1); return; }
                ++stage;
            } else if (stage == 4 && control.tone() == 2 && health.available()) {
                // Exercise the actual window close, not the Stop button.
                if (!window->close()) { loop.exit(1); return; }
                ++stage;
                loop.exit(0);
            } else if ((stage == 1 || stage == 3) && control.tone() == 0 && control.canStart()) {
                if (health.available() || control.pulse() || stop->property("enabled").toBool() ||
                    control.status() != QStringLiteral("Desktop-owned daemon stopped")) {
                    loop.exit(1); return;
                }
                ++stage;
                if (!QMetaObject::invokeMethod(play, "clicked")) { loop.exit(1); }
            }
        });
        if (!QMetaObject::invokeMethod(play, "clicked")) { return 1; }
        check.start(50);
        deadline.start(20000);
        const int result = loop.exec();
        check.stop();
        deadline.stop();
        if (!control.shutdown() || result != 0 || stage != 5 || window->isVisible()) { return 1; }
        std::cout << "M2.9 toolbar start, stop, restart and navigation: PASS\n";
        std::cout << "M2.9 window close with running owned manager: PASS\n";
        return 0;
    }
    if (parser.isSet(health_smoke_test)) {
        // The external synthetic test harness controls the real daemon. This
        // bounded test-only cadence never changes normal 30-second polling.
        if (!parser.isSet(QStringLiteral("ipc-dir"))) { return 1; }
        QEventLoop loop;
        QTimer check;
        QTimer deadline;
        deadline.setSingleShot(true);
        QObject::connect(&deadline, &QTimer::timeout, &loop, [&loop] { loop.exit(1); });
        QObject* root = engine.rootObjects().constFirst();
        QObject* play = root->property("toolbarStartButton").value<QObject*>();
        QObject* stop = root->property("toolbarStopButton").value<QObject*>();
        if (play == nullptr || stop == nullptr || play->property("enabled").toBool() ||
            stop->property("enabled").toBool()) { return 1; }
        int stage = 0;
        QObject::connect(&check, &QTimer::timeout, &loop, [&] {
            if (play->property("enabled").toBool() || stop->property("enabled").toBool() ||
                root->property("toolbarTone").toInt() != control.tone()) { loop.exit(1); return; }
            const bool matches = root->property("currentPageHealthStatus").toString() == health.status() &&
                root->property("currentPageHealthResources").toString() == health.resources() &&
                root->property("currentPageHealthErrors").toString() == health.errors() &&
                root->property("currentPageHealthComponents").toString() == health.components();
            if (!matches) { loop.exit(1); return; }
            if (stage == 0 && health.available()) {
                if (!health.resources().contains(QStringLiteral("KiB")) ||
                    !root->setProperty("navigationRequest", QStringLiteral("settings"))) {
                    loop.exit(1); return;
                }
                stage = 1;
                return; // Let the page replacement settle before inspecting it.
            } else if (stage == 1 && health.available()) {
                if (!scope_page_matches(*root, true, true) ||
                    !root->setProperty("navigationRequest", QStringLiteral("assets"))) { loop.exit(1); return; }
                stage = 2;
                return;
            } else if (stage == 2 && health.available()) {
                if (health.agentRegistryStatus().startsWith(QStringLiteral("Checking"))) { return; }
                if (!root->property("currentPageAgentRosterVisible").toBool() ||
                    !root->property("currentPageAgentRegistry").toString().startsWith(QStringLiteral("Verified registry snapshot")) ||
                    root->property("currentPageApprovedAgents").toString() != QStringLiteral("01010101010101010101010101010101") ||
                    root->property("currentPageRevokedAgents").toString() != QStringLiteral("02020202020202020202020202020202")) {
                    loop.exit(1); return;
                }
                std::cout << "M4.7 GUI approved and revoked registry identities: PASS\n";
                std::cout << "M2.6 GUI connected\n" << std::flush;
                stage = 3;
            } else if (stage == 3 && !health.available() &&
                       health.status() == QStringLiteral("Disconnected or unavailable")) {
                if (health.resources() != QStringLiteral("Uptime, CPU time and memory unavailable.") ||
                    health.errors() != QStringLiteral("Operational error counters unavailable.") ||
                    !root->property("currentPageApprovedAgents").toString().startsWith(QStringLiteral("Unavailable")) ||
                    !root->property("currentPageRevokedAgents").toString().startsWith(QStringLiteral("Unavailable")) ||
                    !root->setProperty("navigationRequest", QStringLiteral("settings"))) {
                    loop.exit(1); return;
                }
                stage = 4;
                return;
            } else if (stage == 4 && !health.available()) {
                if (!scope_page_matches(*root, false)) { loop.exit(1); return; }
                std::cout << "M2.6 GUI disconnected\n" << std::flush;
                stage = 5;
            } else if (stage == 5 && health.available()) {
                if (!scope_page_matches(*root, true, false, true) ||
                    !root->setProperty("navigationRequest", QStringLiteral("assets"))) {
                    loop.exit(1); return;
                }
                stage = 6;
                return;
            } else if (stage == 6 && health.available()) {
                if (health.agentRegistryStatus().startsWith(QStringLiteral("Checking"))) { return; }
                if (!root->property("currentPageAgentRegistry").toString().startsWith(QStringLiteral("Unavailable")) ||
                    !root->property("currentPageApprovedAgents").toString().startsWith(QStringLiteral("Unavailable")) ||
                    !root->property("currentPageRevokedAgents").toString().startsWith(QStringLiteral("Unavailable")) ||
                    !root->setProperty("navigationRequest", QStringLiteral("dashboard"))) { loop.exit(1); return; }
                stage = 7;
                return;
            } else if (stage == 7 && health.available()) {
                if (root->property("currentPageSection").toString() != QStringLiteral("dashboard") ||
                    root->property("currentPageScopeVisible").toBool() ||
                    root->property("currentPageAgentRosterVisible").toBool() ||
                    root->property("currentPageHealthStatus").toString() != health.status()) {
                    loop.exit(1); return;
                }
                std::cout << "M4.7 GUI registry cleared on disconnect and unconfigured restart: PASS\n";
                std::cout << "M3.8 scope connected, denied IPC, disconnected and reconnected: PASS\n";
                std::cout << "M2.6 GUI reconnected: PASS\n" << std::flush;
                loop.exit(0);
                return;
            }
            health.refresh();
        });
        health.start();
        check.start(500);
        deadline.start(15000);
        return loop.exec();
    }
    health.start();
    const int result = app.exec();
    if (!control.shutdown()) {
        std::cerr << "KnetSentry: owned manager shutdown incomplete; private entries preserved.\n";
        return 1;
    }
    return result;
}

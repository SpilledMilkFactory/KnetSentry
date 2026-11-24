// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/build_info.hpp"
#include "service_health_model.hpp"
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
        "KnetSentry M2.9 local manager health and desktop-owned lifecycle; no SIEM monitoring is active."));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption(QCommandLineOption(QStringLiteral("ipc-dir"),
        QStringLiteral("Explicit private manager IPC directory for read-only health."),
        QStringLiteral("absolute-directory")));
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
    parser.process(app);

    // The model outlives QML and is not a management authority.
    knetsentry::desktop::ServiceHealthModel health(parser.value(QStringLiteral("ipc-dir")));
    knetsentry::desktop::DaemonControl control(health, parser.isSet(QStringLiteral("ipc-dir")),
        QDir::cleanPath(QCoreApplication::applicationDirPath() + QStringLiteral("/../manager/knetsentryd")));
    QQmlApplicationEngine engine;
    QQmlEngine::setObjectOwnership(&health, QQmlEngine::CppOwnership);
    QQmlEngine::setObjectOwnership(&control, QQmlEngine::CppOwnership);
    engine.setInitialProperties({{QStringLiteral("healthModel"), QVariant::fromValue(&health)},
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
                    root->property("navigationDepth").toInt() != 1) {
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
        std::cout << "KnetSentry M1.4 primary navigation: PASS (7 sections; no telemetry)\n";
        return 0;
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
                if (!health.resources().contains(QStringLiteral("KiB"))) { loop.exit(1); return; }
                std::cout << "M2.6 GUI connected\n" << std::flush;
                stage = 1;
            } else if (stage == 1 && !health.available() &&
                       health.status() == QStringLiteral("Disconnected or unavailable")) {
                if (health.resources() != QStringLiteral("Uptime, CPU time and memory unavailable.") ||
                    health.errors() != QStringLiteral("Operational error counters unavailable.")) {
                    loop.exit(1); return;
                }
                std::cout << "M2.6 GUI disconnected\n" << std::flush;
                stage = 2;
            } else if (stage == 2 && health.available()) {
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

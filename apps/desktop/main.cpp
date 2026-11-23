// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/build_info.hpp"
#include "knetsentry/core/diagnostics.hpp"

#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QGuiApplication>
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
        "KnetSentry M1.5 Qt Quick/Kirigami visual system; no SIEM monitoring is active."));
    parser.addHelpOption();
    parser.addVersionOption();
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
    parser.process(app);

    // The UI has no privileged interfaces and exposes no operational SIEM
    // state. Actual security data will be supplied by authorized IPC later.
    QQmlApplicationEngine engine;
    engine.loadFromModule("io.github.spilledmilkfactory.KnetSentry", "Main");
    if (engine.rootObjects().size() != 1) {
        publish(knetsentry::core::DiagnosticLevel::Error,
                knetsentry::core::DiagnosticEvent::GuiLoadRejected,
                knetsentry::core::DiagnosticOutcome::Failure);
        std::cerr << "KnetSentry: failed to instantiate the QML root window.\n";
        return 1;
    }
    const auto *window = qobject_cast<QQuickWindow *>(engine.rootObjects().constFirst());
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
    return app.exec();
}

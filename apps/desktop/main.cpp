// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/build_info.hpp"
#include "service_health_model.hpp"
#include "event_explorer_model.hpp"
#include "alert_model.hpp"
#include "dashboard_model.hpp"
#include "workspace_model.hpp"
#include "timeline_model.hpp"
#include "daemon_control.hpp"
#include "knetsentry/core/diagnostics.hpp"

#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDir>
#include <QMetaObject>
#include <unistd.h>
#include <QGuiApplication>
#include <QFontInfo>
#include <QKeyEvent>
#include <QQuickItem>
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

// Resolve controls from the currently displayed page, never a retired page.
QObject* search_control(const QObject& root, const char* name) {
    const auto* page = root.property("currentSectionPage").value<QObject*>();
    return page ? page->property(name).value<QObject*>() : nullptr;
}
bool click_search_control(const QObject& root, const char* name) {
    auto* control = search_control(root, name);
    return control && control->property("enabled").toBool() && QMetaObject::invokeMethod(control, "clicked");
}
bool apply_search_preset(const QObject& root, const char* name, int index) {
    auto* control = search_control(root, name);
    return control && control->property("enabled").toBool() && QMetaObject::invokeMethod(control, "activated", Q_ARG(int, index));
}
bool search_index_matches(const QObject& root, const char* name, int expected) {
    const auto* control = search_control(root, name);
    return control && control->property("currentIndex").toInt() == expected;
}

// Exercise the focused Qt Quick item's real key path. No model mutation here.
void send_key(QQuickWindow& window, int key) {
    QKeyEvent press(QEvent::KeyPress, key, Qt::NoModifier);
    QKeyEvent release(QEvent::KeyRelease, key, Qt::NoModifier);
    QCoreApplication::sendEvent(&window, &press);
    QCoreApplication::sendEvent(&window, &release);
}

bool focus_control(QObject* control) {
    auto* item = qobject_cast<QQuickItem*>(control);
    if (!item || !item->isEnabled() || !item->isVisible()) { return false; }
    item->forceActiveFocus(Qt::TabFocusReason);
    return item->hasActiveFocus();
}

bool keyboard_inspect(QQuickWindow& window, const QObject& root, const char* name, int index) {
    auto* list = search_control(root, name);
    if (!list || index < 0 || index >= list->property("count").toInt() ||
        !focus_control(list) || !list->setProperty("currentIndex", 0)) { return false; }
    send_key(window, Qt::Key_Up);
    if (list->property("currentIndex").toInt() != 0) { return false; }
    if (list->property("count").toInt() > 1) {
        send_key(window, Qt::Key_Down);
        if (list->property("currentIndex").toInt() != 1) { return false; }
        send_key(window, Qt::Key_Up);
        if (list->property("currentIndex").toInt() != 0) { return false; }
    }
    for (int step = 0; step < index; ++step) { send_key(window, Qt::Key_Down); }
    if (list->property("currentIndex").toInt() != index) { return false; }
    send_key(window, Qt::Key_Return);
    return true;
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
    const QCommandLineOption dashboard_smoke_test(QStringLiteral("self-test-dashboard"),
        QStringLiteral("Verify rendered read-only dashboard against a disposable synthetic store."));
    parser.addOption(dashboard_smoke_test);
    const QCommandLineOption dashboard_denied_test(QStringLiteral("self-test-dashboard-denied"),
        QStringLiteral("Verify dashboard refusal against a default-deny manager."));
    parser.addOption(dashboard_denied_test);
    const QCommandLineOption workspace_test(QStringLiteral("self-test-workspace"),
        QStringLiteral("Exercise workspace persistence against an isolated configuration root."), QStringLiteral("mode"));
    parser.addOption(workspace_test);
    const QCommandLineOption timeline_test(QStringLiteral("self-test-timeline"),
        QStringLiteral("Verify rendered timeline against an isolated fixture."), QStringLiteral("mode"));
    parser.addOption(timeline_test);
    parser.process(app);
    bool persistent = true;
    const auto options = parser.optionNames();
    for (const auto& option : options) {
        if (option.startsWith(QStringLiteral("self-test-"))) { persistent = false; }
    }
    // Other integration tests never read or write operator preferences.
    if (parser.isSet(workspace_test)) {
        const auto testRoot = qEnvironmentVariable("XDG_CONFIG_HOME");
        if (!testRoot.startsWith(QStringLiteral("/var/tmp/ks83-")) ||
            QDir::cleanPath(testRoot) != testRoot || testRoot.mid(9).contains(QLatin1Char('/'))) { return 2; }
        persistent = true;
    }
    knetsentry::desktop::WorkspaceModel workspace(persistent);

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
    knetsentry::desktop::DashboardModel dashboard(parser.value(QStringLiteral("ipc-dir")));
    QObject::connect(&health, &knetsentry::desktop::ServiceHealthModel::changed, &dashboard, [&] {
        const auto state = health.queryState();
        if (state == knetsentry::service::HealthQueryState::Unavailable || state == knetsentry::service::HealthQueryState::Invalid) {
            dashboard.clear();
        }
    });
    knetsentry::desktop::TimelineModel timeline(parser.value(QStringLiteral("ipc-dir")));
    QObject::connect(&health, &knetsentry::desktop::ServiceHealthModel::changed, &timeline, [&] {
        const auto state = health.queryState();
        if (state == knetsentry::service::HealthQueryState::Unavailable || state == knetsentry::service::HealthQueryState::Invalid) { timeline.clear(); }
    });
    QQmlApplicationEngine engine;
    QQmlEngine::setObjectOwnership(&timeline, QQmlEngine::CppOwnership);
    QQmlEngine::setObjectOwnership(&workspace, QQmlEngine::CppOwnership);
    QQmlEngine::setObjectOwnership(&dashboard, QQmlEngine::CppOwnership);
    QQmlEngine::setObjectOwnership(&alerts, QQmlEngine::CppOwnership);
    QQmlEngine::setObjectOwnership(&events, QQmlEngine::CppOwnership);
    QQmlEngine::setObjectOwnership(&health, QQmlEngine::CppOwnership);
    QQmlEngine::setObjectOwnership(&control, QQmlEngine::CppOwnership);
    const int platformFontPixels = QFontInfo(app.font()).pixelSize();
    engine.setInitialProperties({{QStringLiteral("platformFontPixels"), platformFontPixels > 0 ? platformFontPixels : 14},
                                 {QStringLiteral("timelineModel"), QVariant::fromValue(&timeline)},
                                 {QStringLiteral("workspaceModel"), QVariant::fromValue(&workspace)},
                                 {QStringLiteral("dashboardModel"), QVariant::fromValue(&dashboard)},
                                 {QStringLiteral("alertModel"), QVariant::fromValue(&alerts)},
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
    if (parser.isSet(workspace_test)) {
        const auto mode = parser.value(workspace_test);
        QCoreApplication::processEvents();
        if (window->width() != 1920 || window->height() != 1080 ||
            window->visibility() != QWindow::Windowed) {
            std::cerr << "M8.3 default windowed geometry: FAIL\n";
            return 1;
        }
        std::cout << "M8.3 default windowed geometry: PASS\n";
        if (mode == QStringLiteral("write")) {
            auto* button = window->property("workspaceEvidenceButton").value<QObject*>();
            if (!button || !QMetaObject::invokeMethod(button, "clicked")) { return 1; }
            auto* resize = window->property("workspaceResizeControl").value<QObject*>();
            if (!resize || !resize->setProperty("value", 65) ||
                !QMetaObject::invokeMethod(resize, "valueModified")) { return 1; }
            auto* save = window->property("workspaceSaveButton").value<QObject*>();
            if (!save || !QMetaObject::invokeMethod(save, "clicked")) { return 1; }
        } else if (mode != QStringLiteral("restore") && mode != QStringLiteral("default")) { return 2; }
        QCoreApplication::processEvents();
        const bool defaults = mode == QStringLiteral("default");
        if (workspace.ratio() != (defaults ? 50 : 65) || !workspace.charts() ||
            workspace.health() != defaults || workspace.telemetry() != defaults ||
            window->property("workspaceHealthVisible").toBool() != defaults ||
            window->property("workspaceTelemetryVisible").toBool() != defaults ||
            !window->property("workspaceChartsVisible").toBool() ||
            !window->property("currentDashboardHistogramCounts").toString().isEmpty()) { return 1; }
        auto settle = [] {
            QEventLoop loop;
            QTimer::singleShot(200, &loop, &QEventLoop::quit);
            loop.exec();
        };
        window->resize(1600, 900);
        settle();
        if (window->property("workspaceColumns").toInt() != 2 ||
            window->property("workspaceOverviewWidth").toReal() <= 0 ||
            window->property("workspaceChartWidth").toReal() <= 0 ||
            (!defaults && window->property("workspaceOverviewWidth").toReal() <=
                          window->property("workspaceChartWidth").toReal())) { return 1; }
        window->resize(700, 600);
        settle();
        if (window->property("workspaceColumns").toInt() != 1) { return 1; }
        if (!window->setProperty("navigationRequest", QStringLiteral("assets"))) { return 1; }
        QCoreApplication::processEvents();
        if (!window->property("currentPageTelemetryVisible").toBool()) { return 1; }
        std::cout << "M8.3 workspace rendered preferences: PASS\n";
        return 0;
    }
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
        auto* motionToggle = root->property("reduceMotionControl").value<QObject*>();
        if (!motionToggle || !motionToggle->property("checked").toBool() ||
            root->property("motionDuration").toInt() != 0 ||
            root->property("navigationAnimationRunning").toBool() ||
            root->property("loadingAnimationRunning").toBool() ||
            root->property("operationFeedbackVisible").toBool() ||
            root->property("displayedHealthPulse").toBool()) { return 1; }
        if (!motionToggle->setProperty("checked", false) ||
            !QMetaObject::invokeMethod(motionToggle, "toggled") || root->property("reduceMotion").toBool()) { return 1; }
        const int platform = root->property("platformMotionDuration").toInt();
        const int duration = root->property("motionDuration").toInt();
        if ((platform <= 1 && duration != 0) || (platform > 1 && (duration <= 0 || duration > 120 || duration > platform))) { return 1; }
        // Rapid navigation must be immediate, bounded and independent of motion.
        for (int pass = 0; pass < 16; ++pass) {
            const auto section = pass % 2 == 0 ? QStringLiteral("dashboard") : QStringLiteral("settings");
            if (!root->setProperty("navigationRequest", section) ||
                root->property("activeSection").toString() != section ||
                root->property("navigationDepth").toInt() != 1) { return 1; }
        }
        if (root->property("motionAllowed").toBool() != root->property("navigationAnimationRunning").toBool()) { return 1; }
        if (!motionToggle->setProperty("checked", true) || !QMetaObject::invokeMethod(motionToggle, "toggled") ||
            !root->property("reduceMotion").toBool() || root->property("motionDuration").toInt() != 0 ||
            root->property("navigationAnimationRunning").toBool() || root->property("loadingAnimationRunning").toBool() ||
            root->property("displayedHealthPulse").toBool()) { return 1; }
        const int base = root->property("scaledBodySize").toInt();
        if (base < 1 || root->property("textScalePercent").toInt() != 100 || !apply_search_preset(*root, "textScaleControl", 2) ||
            root->property("textScalePercent").toInt() != 150 ||
            root->property("scaledBodySize").toInt() <= base ||
            !root->setProperty("navigationRequest", QStringLiteral("events")) ||
            root->property("textScalePercent").toInt() != 150 ||
            !focus_control(search_control(*root, "keyboardContent")) ||
            !root->setProperty("navigationRequest", QStringLiteral("settings")) ||
            !search_index_matches(*root, "textScaleControl", 2) ||
            !apply_search_preset(*root, "textScaleControl", 0) ||
            root->property("scaledBodySize").toInt() != base ||
            !focus_control(root->property("navigationFocusControl").value<QObject*>())) { return 1; }
        if (!apply_search_preset(*root, "textScaleControl", 2)) { return 1; }
        window->resize(700, 600);
        QEventLoop scaleLayout;
        QTimer::singleShot(200, &scaleLayout, &QEventLoop::quit);
        scaleLayout.exec();
        if (!root->property("currentPageCompact").toBool() ||
            !apply_search_preset(*root, "textScaleControl", 0)) { return 1; }
        std::cout << "M8.7 rendered text scale and focus targets: PASS\n";
        std::cout << "M8.5 motion opt-in, bounded navigation and immediate cancellation: PASS\n";
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
    if (parser.isSet(timeline_test)) {
        const auto mode = parser.value(timeline_test);
        if (!timeline.configured() || (mode != QStringLiteral("read") && mode != QStringLiteral("denied"))) { return 1; }
        QObject* root = engine.rootObjects().constFirst();
        if (!root->setProperty("navigationRequest", QStringLiteral("investigations"))) { return 1; }
        auto* refresh = root->property("timelineRefreshButton").value<QObject*>();
        if (refresh == nullptr || !QMetaObject::invokeMethod(refresh, "clicked")) { return 1; }
        QEventLoop loop;
        QTimer check, deadline;
        int stage = 0;
        deadline.setSingleShot(true);
        QObject::connect(&deadline, &QTimer::timeout, &loop, [&loop] { loop.exit(1); });
        QObject::connect(&check, &QTimer::timeout, &loop, [&] {
            if (timeline.busy()) { return; }
            if (mode == QStringLiteral("denied")) {
                loop.exit(timeline.entries().isEmpty() && timeline.status().startsWith(QStringLiteral("Unavailable")) &&
                    root->property("currentTimelineCount").toInt() == 0 ? 0 : 1); return;
            }
            if (stage == 0) {
                if (root->property("currentTimelineCount").toInt() != 16 || timeline.entries().size() != 16 ||
                    !timeline.entries().at(0).startsWith(QStringLiteral("1005 | Event #5")) ||
                    !timeline.entries().at(8).startsWith(QStringLiteral("1013 | Alert 1/2"))) { loop.exit(1); return; }
                if (!keyboard_inspect(*window, *root, "timelineKeyboardList", 0)) { loop.exit(1); return; }
                if (timeline.related().isEmpty() || !root->property("currentTimelineDetail").toString().contains(QStringLiteral("Receiver time (Unix ms): 1005"))) { loop.exit(1); return; }
                timeline.follow(0);
                if (timeline.evidence().isEmpty() || !root->property("currentTimelineDetail").toString().startsWith(QStringLiteral("Alert"))) { loop.exit(1); return; }
                if (!keyboard_inspect(*window, *root, "timelineKeyboardList", 8)) { loop.exit(1); return; } // first alert references off-page evidence
                timeline.verifyEvidence(-1);
                if (timeline.busy() || timeline.evidence().isEmpty()) { loop.exit(1); return; }
                timeline.verifyEvidence(0); stage = 1; return;
            }
            if (!root->property("currentTimelineEvidence").toString().startsWith(QStringLiteral("Verified evidence #1")) ||
                !root->setProperty("navigationRequest", QStringLiteral("dashboard")) || !timeline.entries().isEmpty() ||
                !timeline.detail().isEmpty() || !timeline.evidenceDetail().isEmpty()) { loop.exit(1); return; }
            loop.exit(0);
        });
        deadline.start(12000); check.start(25);
        const int result = loop.exec();
        if (result == 0) {
            if (mode == QStringLiteral("read")) { std::cout << "M8.7 timeline keyboard inspection: PASS\n"; }
            std::cout << "M8.4 rendered timeline and evidence lifecycle: PASS\n";
        }
        return result;
    }
    if (parser.isSet(dashboard_smoke_test) || parser.isSet(dashboard_denied_test)) {
        if (!dashboard.configured()) { return 1; }
        QObject* root = engine.rootObjects().constFirst();
        QObject* refresh = root->property("dashboardRefreshButton").value<QObject*>();
        if (refresh == nullptr || !root->property("currentDashboardEvents").toString().startsWith(QStringLiteral("Unavailable")) ||
            !QMetaObject::invokeMethod(refresh, "clicked")) { return 1; }
        // The real pending request must remain visible even with reduced motion.
        if (!dashboard.busy() || !root->property("operationFeedbackVisible").toBool() ||
            root->property("loadingAnimationRunning").toBool() ||
            root->property("operationFeedbackText").toString() != QStringLiteral("Stored request in progress…")) { return 1; }
        if (!root->setProperty("reduceMotion", false) ||
            root->property("loadingAnimationRunning").toBool() != root->property("motionAllowed").toBool() ||
            !root->property("operationFeedbackVisible").toBool() ||
            !root->setProperty("reduceMotion", true) || root->property("loadingAnimationRunning").toBool() ||
            !root->property("operationFeedbackVisible").toBool()) { return 1; }
        QEventLoop loop;
        QTimer check, deadline;
        deadline.setSingleShot(true);
        QObject::connect(&deadline, &QTimer::timeout, &loop, [&loop] { loop.exit(1); });
        QObject::connect(&check, &QTimer::timeout, &loop, [&] {
            if (dashboard.busy()) { return; }
            if (root->property("operationFeedbackVisible").toBool() ||
                root->property("loadingAnimationRunning").toBool()) { loop.exit(1); return; }
            std::cout << "M8.5 actual request feedback and completion: PASS\n";
            const auto eventsText = root->property("currentDashboardEvents").toString();
            const auto alertsText = root->property("currentDashboardAlerts").toString();
            const auto detectionText = root->property("currentDashboardDetections").toString();
            if (parser.isSet(dashboard_denied_test)) {
                if (!eventsText.startsWith(QStringLiteral("Unavailable")) ||
                    !alertsText.startsWith(QStringLiteral("Unavailable")) ||
                    !detectionText.startsWith(QStringLiteral("Unavailable")) ||
                    !root->property("currentDashboardHistogramCounts").toString().isEmpty() ||
                    !root->property("currentDashboardActivityCounts").toString().isEmpty() ||
                    !root->property("currentDashboardSeverityCounts").toString().isEmpty()) { loop.exit(1); return; }
                std::cout << "M8.1 rendered denied summaries: PASS\n";
                loop.exit(0); return;
            }
            const auto chartMatches = [root](const char* property, const char* expected) {
                return root->property(property).toString() == QString::fromLatin1(expected);
            };
            QObject* outcomeFilter = root->property("dashboardActivityFilter").value<QObject*>();
            QObject* severityFilter = root->property("dashboardSeverityFilter").value<QObject*>();
            if (outcomeFilter == nullptr || severityFilter == nullptr ||
                !chartMatches("currentDashboardHistogramCounts", "0,0,8") ||
                !chartMatches("currentDashboardActivityCounts", "0,0,0,8") ||
                !chartMatches("currentDashboardSeverityCounts", "0,0,0,8,0,0") ||
                !QMetaObject::invokeMethod(outcomeFilter, "activated", Q_ARG(int, 2)) ||
                !chartMatches("currentDashboardActivityCounts", "0,0,0,0") ||
                !chartMatches("currentDashboardHistogramCounts", "0,0,8") ||
                !QMetaObject::invokeMethod(outcomeFilter, "activated", Q_ARG(int, 3)) ||
                !chartMatches("currentDashboardActivityCounts", "0,0,0,8") ||
                !QMetaObject::invokeMethod(severityFilter, "activated", Q_ARG(int, 1)) ||
                dashboard.severityFilter() != 1 || !chartMatches("currentDashboardSeverityCounts", "0,0,0,8,0,0")) {
                loop.exit(1); return;
            }
            // Exercise repeated local selections without refreshing or widening the evidence query.
            for (int iteration = 0; iteration < 64; ++iteration) {
                const int filter = iteration % 2 == 0 ? 2 : 3;
                if (!QMetaObject::invokeMethod(outcomeFilter, "activated", Q_ARG(int, filter)) ||
                    !chartMatches("currentDashboardActivityCounts", filter == 2 ? "0,0,0,0" : "0,0,0,8")) {
                    loop.exit(1); return;
                }
            }
            dashboard.setActivityFilter(-1);
            dashboard.setSeverityFilter(2);
            if (dashboard.activityFilter() != 3 || dashboard.severityFilter() != 1 || dashboard.busy()) { loop.exit(1); return; }
            if (!eventsText.startsWith(QStringLiteral("8 stored events on page; 8 failure outcomes.")) ||
                !alertsText.startsWith(QStringLiteral("8 active stored alerts on page (8 open, 0 acknowledged)")) ||
                !detectionText.startsWith(QStringLiteral("1 distinct rule identifiers in 8 stored alerts")) ||
                !eventsText.contains(QStringLiteral("More records exist.")) || !alertsText.contains(QStringLiteral("More records exist.")) ||
                !root->setProperty("navigationRequest", QStringLiteral("assets")) ||
                !dashboard.eventSummary().startsWith(QStringLiteral("Unavailable")) ||
                !dashboard.alertSummary().startsWith(QStringLiteral("Unavailable")) ||
                !dashboard.eventHistogram().isEmpty() || !dashboard.activityCounts().isEmpty() ||
                !dashboard.severityCounts().isEmpty() || dashboard.activityFilter() != 0 || dashboard.severityFilter() != 0) { loop.exit(1); return; }
            std::cout << "M8.1 rendered stored summaries and navigation clearing: PASS\n";
            std::cout << "M8.2 rendered chart values, local filters and clearing: PASS\n";
            loop.exit(0);
        });
        check.start(25); deadline.start(10000);
        return loop.exec();
    }
    if (parser.isSet(events_smoke_test)) {
        if (!parser.isSet(QStringLiteral("ipc-dir"))) { return 1; }
        QObject* root = engine.rootObjects().constFirst();
        if (!root->setProperty("navigationRequest", QStringLiteral("events"))) { return 1; }
        QCoreApplication::processEvents();
        // Exercise the actual preset, save, cross-view and restore handlers
        // without executing a stored request. Categorical views exclude source.
        auto* source = search_control(*root, "eventSourceControl");
        if (!source || !apply_search_preset(*root, "eventPresetControl", 1) ||
            !search_index_matches(*root, "eventCollectorControl", 2) ||
            !search_index_matches(*root, "eventOutcomeControl", 3) ||
            !search_index_matches(*root, "eventOrderControl", 1) ||
            !source->setProperty("text", QStringLiteral("ssh.service")) ||
            !click_search_control(*root, "eventSaveControl") || events.busy() || events.rowCount() != 0 ||
            !click_search_control(*root, "searchAlertsRoute") ||
            root->property("activeSection").toString() != QStringLiteral("alerts") || alerts.busy() || alerts.rowCount() != 0 ||
            !click_search_control(*root, "searchEventsRoute") ||
            root->property("activeSection").toString() != QStringLiteral("events") ||
            !click_search_control(*root, "eventRestoreControl")) { return 1; }
        source = search_control(*root, "eventSourceControl");
        if (!source || !source->property("text").toString().isEmpty() ||
            !search_index_matches(*root, "eventCollectorControl", 2) ||
            !search_index_matches(*root, "eventOutcomeControl", 3) ||
            !search_index_matches(*root, "eventOrderControl", 1) ||
            !click_search_control(*root, "eventForgetControl") ||
            !apply_search_preset(*root, "eventPresetControl", 0) || events.busy() || events.rowCount() != 0) { return 1; }
        events.search(QStringLiteral("*.service"), -1, -1, false);
        if (events.busy() || events.rowCount() != 0 || !events.status().startsWith(QStringLiteral("Invalid"))) { return 1; }
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
                if (count != 8 || !events.more() || !events.status().contains(QStringLiteral("More matching records available.")) ||
                    !events.data(events.index(0, 0), Qt::DisplayRole).toString().startsWith(QStringLiteral("#1 ·"))) { loop.exit(1); return; }
                if (!keyboard_inspect(*window, *root, "eventKeyboardList", 0)) { loop.exit(1); return; }
                if (!root->property("currentEventDetail").toString().startsWith(QStringLiteral("Event ID: 1\n")) ||
                    !root->property("currentEventStatus").toString().contains(QStringLiteral("stored snapshot")) ||
                    !QMetaObject::invokeMethod(next_button, "clicked")) { loop.exit(1); return; }
                ++stage;
            } else if (stage == 1) {
                if (count != 8 || !events.more() || !events.detail().isEmpty() ||
                    !events.data(events.index(0, 0), Qt::DisplayRole).toString().startsWith(QStringLiteral("#9 ·"))) { loop.exit(1); return; }
                auto* exactSource = search_control(*root, "eventSourceControl");
                if (!apply_search_preset(*root, "eventPresetControl", 1) || !exactSource ||
                    !exactSource->setProperty("text", QStringLiteral("ssh.service")) ||
                    events.busy() || events.rowCount() != 0 || events.more() ||
                    !QMetaObject::invokeMethod(search_button, "clicked")) { loop.exit(1); return; }
                ++stage;
            } else if (stage == 2) {
                if (count != 8 || !events.more() || !events.data(events.index(0, 0), Qt::DisplayRole).toString().startsWith(QStringLiteral("#20 ·"))) { loop.exit(1); return; }
                events.select(0);
                if (events.detail().isEmpty() || !click_search_control(*root, "searchTimelineRoute") ||
                    root->property("activeSection").toString() != QStringLiteral("investigations") ||
                    events.rowCount() != 0 || events.more() || !events.detail().isEmpty() || timeline.busy() || !timeline.entries().isEmpty() ||
                    !click_search_control(*root, "searchEventsRoute")) { loop.exit(1); return; }
                events.search(QStringLiteral("fixture.service"), -1, -1, false);
                ++stage;
            } else {
                if (count != 0 || events.more() || !root->property("currentEventStatus").toString().startsWith(QStringLiteral("No matching stored events")) ||
                    !root->setProperty("navigationRequest", QStringLiteral("dashboard")) || events.rowCount() != 0 || !events.detail().isEmpty()) { loop.exit(1); return; }
                std::cout << "M8.7 event keyboard inspection: PASS\n";
                std::cout << "M8.6 rendered event presets, saved views and cross-view clearing: PASS\n";
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
        if (!apply_search_preset(*root, "alertPresetControl", 1) ||
            !search_index_matches(*root, "alertSeverityControl", 4) ||
            !click_search_control(*root, "alertSaveControl") || alerts.busy() || alerts.rowCount() != 0 ||
            !click_search_control(*root, "searchTimelineRoute") ||
            root->property("activeSection").toString() != QStringLiteral("investigations") || timeline.busy() || !timeline.entries().isEmpty() ||
            !click_search_control(*root, "searchAlertsRoute") ||
            root->property("activeSection").toString() != QStringLiteral("alerts") ||
            !click_search_control(*root, "alertRestoreControl") ||
            !search_index_matches(*root, "alertSeverityControl", 4) || alerts.busy() || alerts.rowCount() != 0 ||
            !apply_search_preset(*root, "alertPresetControl", 0)) { return 1; }
        alerts.search(6);
        if (alerts.busy() || alerts.rowCount() != 0 || !alerts.status().startsWith(QStringLiteral("Invalid"))) { return 1; }
        QObject* refresh = root->property("currentAlertRefreshButton").value<QObject*>();
        QObject* ack = root->property("currentAlertAckButton").value<QObject*>();
        if (!refresh || !ack || !QMetaObject::invokeMethod(refresh,"clicked")) { return 1; }
        QEventLoop loop; QTimer check; QTimer deadline; deadline.setSingleShot(true); int stage = 0;
        QObject::connect(&deadline,&QTimer::timeout,&loop,[&loop] { loop.exit(1); });
        QObject::connect(&check,&QTimer::timeout,&loop,[&] {
            if (alerts.busy()) { return; }
            if (stage == 0) {
                if (root->property("currentAlertCount").toInt() != 8 || !alerts.more()) { loop.exit(1); return; }
                if (!keyboard_inspect(*window, *root, "alertKeyboardList", 1)) { loop.exit(1); return; } // first alert already acknowledged
                if (!root->property("currentAlertDetail").toString().contains(QStringLiteral("Alert 1/3")) || !alerts.canAcknowledge()) { loop.exit(1); return; }
                alerts.inspectEvidence(0); ++stage;
            } else if (stage == 1) {
                if (!root->property("currentAlertEvidence").toString().contains(QStringLiteral("Verified stored evidence #2")) || !QMetaObject::invokeMethod(ack,"clicked")) { loop.exit(1); return; }
                ++stage;
            } else if (stage == 2) {
                if (!alerts.status().startsWith(QStringLiteral("Acknowledgement committed"))) { loop.exit(1); return; }
                if (!click_search_control(*root, "alertRestoreControl") ||
                    !search_index_matches(*root, "alertSeverityControl", 4) ||
                    !click_search_control(*root, "alertForgetControl") || alerts.busy() || alerts.rowCount() != 0 ||
                    !QMetaObject::invokeMethod(refresh, "clicked")) { loop.exit(1); return; }
                ++stage;
            } else if (stage == 3) {
                alerts.select(1);
                if (alerts.rowCount() != 8 || alerts.canAcknowledge() || !alerts.detail().contains(QStringLiteral("Acknowledged"))) { loop.exit(1); return; }
                alerts.next(); ++stage;
            } else if (stage == 4) {
                if (alerts.rowCount() != 3 || alerts.more() || !alerts.status().contains(QStringLiteral("End of matching results."))) { loop.exit(1); return; }
                alerts.select(0);
                if (alerts.detail().isEmpty() || !click_search_control(*root, "searchEventsRoute") ||
                    root->property("activeSection").toString() != QStringLiteral("events") ||
                    alerts.rowCount() != 0 || alerts.more() || !alerts.detail().isEmpty() || alerts.canAcknowledge() ||
                    events.busy() || events.rowCount() != 0 || !click_search_control(*root, "searchAlertsRoute")) { loop.exit(1); return; }
                auto* currentRefresh = root->property("currentAlertRefreshButton").value<QObject*>();
                if (!apply_search_preset(*root, "alertPresetControl", 2) || alerts.busy() || alerts.rowCount() != 0 || alerts.more() ||
                    !currentRefresh || !QMetaObject::invokeMethod(currentRefresh, "clicked")) { loop.exit(1); return; }
                ++stage;
            } else {
                if (alerts.rowCount() != 0 || !alerts.status().startsWith(QStringLiteral("No matching")) || !root->setProperty("navigationRequest",QStringLiteral("dashboard")) || alerts.rowCount() != 0 || !alerts.detail().isEmpty()) { loop.exit(1); return; }
                std::cout << "M8.7 alert keyboard inspection: PASS\n";
                std::cout << "M8.6 rendered alert presets, saved views and cross-view clearing: PASS\n";
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
                    health.dashboardRegistry() != QStringLiteral("1 approved, 1 revoked registry identities (not live sessions).\n"
                                                                  "Monitored assets unavailable.") ||
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
                    !health.dashboardRegistry().startsWith(QStringLiteral("Unavailable")) ||
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
                    !health.dashboardRegistry().startsWith(QStringLiteral("Unavailable")) ||
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

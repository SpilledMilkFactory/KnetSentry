// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import io.github.spilledmilkfactory.KnetSentry

// M2.6: read-only daemon health; no live SIEM telemetry sources.
Kirigami.ApplicationWindow {
    id: window
    // Session-only magnification of the platform font, not a security setting.
    required property int platformFontPixels
    property int textScalePercent: 100
    readonly property real effectiveTextScale: font.pixelSize / 14.0
    function applyTextScale(percent: int): void {
        if (percent === 100 || percent === 125 || percent === 150)
            textScalePercent = percent
    }
    font.pixelSize: Math.round(platformFontPixels * textScalePercent / 100.0)
    readonly property alias navigationFocusControl: navigationButton
    readonly property int scaledBodySize: designTokens.bodySize
    onActiveFocusItemChanged: {
        if (currentSectionPage && activeFocusItem)
            currentSectionPage.revealKeyboardFocus(activeFocusItem)
    }
    Shortcut {
        sequence: "F6"
        onActivated: {
            if (window.currentSectionPage)
                window.currentSectionPage.focusPrimary()
        }
    }
    Shortcut {
        sequence: "Shift+F6"
        onActivated: navigationButton.forceActiveFocus(Qt.BacktabFocusReason)
    }
    required property TimelineModel timelineModel
    SearchViews { id: savedSearchViews }
    readonly property Controls.Button timelineRefreshButton: currentSectionPage ? currentSectionPage.timelineRefreshButton : null
    readonly property int currentTimelineCount: currentSectionPage ? currentSectionPage.timelineCount : 0
    readonly property string currentTimelineDetail: currentSectionPage ? currentSectionPage.timelineDetail : ""
    readonly property string currentTimelineEvidence: currentSectionPage ? currentSectionPage.timelineEvidence : ""
    required property WorkspaceModel workspaceModel
    required property DashboardModel dashboardModel
    readonly property Controls.Button workspaceEvidenceButton: currentSectionPage ? currentSectionPage.workspaceEvidenceButton : null
    readonly property Controls.Button workspaceSaveButton: currentSectionPage ? currentSectionPage.workspaceSaveButton : null
    readonly property Controls.SpinBox workspaceResizeControl: currentSectionPage ? currentSectionPage.workspaceResizeControl : null
    readonly property bool workspaceHealthVisible: currentSectionPage ? currentSectionPage.workspaceHealthVisible : false
    readonly property bool workspaceTelemetryVisible: currentSectionPage ? currentSectionPage.telemetryVisible : false
    readonly property int workspaceColumns: currentSectionPage ? currentSectionPage.workspaceColumns : 0
    readonly property real workspaceOverviewWidth: currentSectionPage ? currentSectionPage.workspaceOverviewWidth : 0
    readonly property real workspaceChartWidth: currentSectionPage ? currentSectionPage.workspaceChartWidth : 0
    readonly property bool workspaceChartsVisible: currentSectionPage ? currentSectionPage.workspaceChartsVisible : false
    required property ServiceHealthModel healthModel
    required property AlertModel alertModel
    required property EventExplorerModel eventModel
    required property DaemonControl daemonControl
    readonly property alias toolbarStartButton: startButton
    readonly property alias toolbarStopButton: stopButton
    readonly property int toolbarTone: window.daemonControl.tone
    readonly property bool toolbarPulse: window.daemonControl.pulse
    // Session-only, fail-safe opt-in. Respect the platform's duration hint as
    // well as the operator's choice; never animate security-relevant data.
    property bool reduceMotion: true
    readonly property int platformMotionDuration: Kirigami.Units.shortDuration
    readonly property int motionDuration: reduceMotion || platformMotionDuration <= 1
        ? 0 : (platformMotionDuration < designTokens.durationFast ? platformMotionDuration : designTokens.durationFast)
    readonly property bool motionAllowed: motionDuration > 0 && visible && visibility !== Window.Minimized
    readonly property bool navigationAnimationRunning: navigationMotion.running
    readonly property bool loadingAnimationRunning: loadingMotion.running
    readonly property bool displayedHealthPulse: heartbeat.activePulse
    readonly property bool operationFeedbackVisible: requestFeedback.visible
    readonly property string operationFeedbackText: requestLabel.text
    readonly property alias reduceMotionControl: motionToggle
    readonly property bool operationPending: (activeSection === "dashboard" && dashboardModel.busy)
        || (activeSection === "events" && eventModel.busy)
        || (activeSection === "alerts" && alertModel.busy)
        || (activeSection === "investigations" && timelineModel.busy)
    onMotionAllowedChanged: {
        if (!motionAllowed && navigationMotion)
            navigationMotion.stop()
    }
    objectName: "knetSentryMainWindow"
    title: qsTr("KnetSentry — %1").arg(activeSectionTitle)
    // Default client size in logical pixels; do not maximize or enter fullscreen.
    width: 1920
    height: 1080
    minimumWidth: 700
    minimumHeight: 480
    visible: true

    DesignTokens { id: designTokens; textScale: window.effectiveTextScale }
    readonly property string visualSystemVersion: designTokens.version
    readonly property bool visualTokensValid: designTokens.spaceXs < designTokens.spaceS
                                              && designTokens.spaceS < designTokens.spaceL
                                              && designTokens.touchTarget >= 40
                                              && !designTokens.animateStatusChanges
    readonly property SectionPage currentSectionPage: pageStack.currentItem as SectionPage
    readonly property string currentPageVisualSystem: currentSectionPage
                                                       ? currentSectionPage.visualSystemVersion : ""
    readonly property bool currentPageCompact: currentSectionPage
                                               ? currentSectionPage.compactLayout : false

    // Public, non-privileged navigation state. Used by the headless C++
    // integration test to exercise exactly the same routing as drawer actions.
    property string activeSection: "dashboard"
    onActiveSectionChanged: {
        if (window.timelineModel && activeSection !== "investigations")
            window.timelineModel.clear()
        if (window.dashboardModel && activeSection !== "dashboard")
            window.dashboardModel.clear()
        if (window.alertModel && activeSection !== "alerts")
            window.alertModel.clear()
        if (window.eventModel && activeSection !== "events")
            window.eventModel.clear()
    }
    property string navigationRequest: ""
    readonly property string currentDashboardEvents: currentSectionPage ? currentSectionPage.dashboardEvents : ""
    readonly property string currentDashboardAlerts: currentSectionPage ? currentSectionPage.dashboardAlerts : ""
    readonly property string currentDashboardDetections: currentSectionPage ? currentSectionPage.dashboardDetections : ""
    readonly property string currentDashboardHistogramCounts: currentSectionPage ? currentSectionPage.dashboardHistogramCounts : ""
    readonly property string currentDashboardActivityCounts: currentSectionPage ? currentSectionPage.dashboardActivityCounts : ""
    readonly property string currentDashboardSeverityCounts: currentSectionPage ? currentSectionPage.dashboardSeverityCounts : ""
    readonly property Controls.ComboBox dashboardActivityFilter: currentSectionPage ? currentSectionPage.dashboardActivityFilter : null
    readonly property Controls.ComboBox dashboardSeverityFilter: currentSectionPage ? currentSectionPage.dashboardSeverityFilter : null
    readonly property Controls.Button dashboardRefreshButton: currentSectionPage ? currentSectionPage.dashboardRefreshButton : null
    readonly property string currentPageHealthStatus: currentSectionPage
        ? currentSectionPage.displayedHealthStatus : ""
    readonly property string currentPageHealthResources: currentSectionPage
        ? currentSectionPage.displayedHealthResources : ""
    readonly property string currentPageHealthErrors: currentSectionPage
        ? currentSectionPage.displayedHealthErrors : ""
    readonly property string currentPageHealthComponents: currentSectionPage
        ? currentSectionPage.displayedHealthComponents : ""
    readonly property bool currentPageAgentRosterVisible: currentSectionPage ? currentSectionPage.agentRosterVisible : false
    readonly property string currentPageAgentRegistry: currentSectionPage ? currentSectionPage.displayedAgentRegistry : ""
    readonly property string currentPageApprovedAgents: currentSectionPage ? currentSectionPage.displayedApprovedAgents : ""
    readonly property string currentPageRevokedAgents: currentSectionPage ? currentSectionPage.displayedRevokedAgents : ""
    readonly property bool currentPageTelemetryVisible: currentSectionPage ? currentSectionPage.telemetryVisible : false
    readonly property string currentPageTelemetryStatus: currentSectionPage ? currentSectionPage.displayedTelemetryStatus : ""
    readonly property string currentPageTelemetryCollector: currentSectionPage ? currentSectionPage.displayedTelemetryCollector : ""
    readonly property string currentPageTelemetryHealth: currentSectionPage ? currentSectionPage.displayedTelemetryHealth : ""
    readonly property string currentPageTelemetryRate: currentSectionPage ? currentSectionPage.displayedTelemetryRate : ""
    readonly property string currentPageTelemetryQueue: currentSectionPage ? currentSectionPage.displayedTelemetryQueue : ""
    readonly property string currentPageTelemetryFailure: currentSectionPage ? currentSectionPage.displayedTelemetryFailure : ""
    readonly property bool currentPageScopeVisible: currentSectionPage ? currentSectionPage.scopeVisible : false
    readonly property string currentPageScopeState: currentSectionPage ? currentSectionPage.displayedScopeState : ""
    readonly property string currentPageScopeNetworks: currentSectionPage ? currentSectionPage.displayedScopeNetworks : ""
    readonly property string currentPageScopeInterfaces: currentSectionPage ? currentSectionPage.displayedScopeInterfaces : ""
    readonly property string currentPageScopeDenials: currentSectionPage ? currentSectionPage.displayedScopeDenials : ""
    readonly property int currentAlertCount: currentSectionPage ? currentSectionPage.alertCount : 0
    readonly property string currentAlertDetail: currentSectionPage ? currentSectionPage.alertDetail : ""
    readonly property string currentAlertEvidence: currentSectionPage ? currentSectionPage.alertEvidence : ""
    readonly property Controls.Button currentAlertRefreshButton: currentSectionPage ? currentSectionPage.alertRefreshButton : null
    readonly property Controls.Button currentAlertAckButton: currentSectionPage ? currentSectionPage.alertAckButton : null
    readonly property int currentEventCount: currentSectionPage ? currentSectionPage.eventCount : 0
    readonly property string currentEventStatus: currentSectionPage ? currentSectionPage.eventStatus : ""
    readonly property string currentEventDetail: currentSectionPage ? currentSectionPage.eventDetail : ""
    readonly property Controls.Button currentEventSearchButton: currentSectionPage ? currentSectionPage.eventSearchButton : null
    readonly property Controls.Button currentEventNextButton: currentSectionPage ? currentSectionPage.eventNextButton : null
    readonly property string currentPageSection: currentSectionPage
                                                 ? currentSectionPage.sectionId : ""
    readonly property int navigationDepth: pageStack.depth
    readonly property string activeSectionTitle: {
        switch (activeSection) {
        case "dashboard": return qsTr("Dashboard")
        case "assets": return qsTr("Assets")
        case "events": return qsTr("Events")
        case "detections": return qsTr("Detections")
        case "alerts": return qsTr("Alerts")
        case "investigations": return qsTr("Investigations")
        case "settings": return qsTr("Settings")
        default: return qsTr("Unknown")
        }
    }

    function isValidSection(sectionId) {
        return ["dashboard", "assets", "events", "detections", "alerts",
                "investigations", "settings"].indexOf(sectionId) !== -1
    }

    function navigateTo(sectionId) {
        if (!isValidSection(sectionId)) {
            return false
        }
        if (activeSection === sectionId) {
            return true
        }
        // These are TOP-LEVEL destinations, not drill-down history. Replacing
        // the current page keeps the navigation stack bounded at depth one.
        // Kirigami 6.24 can warn about temporarily unparented graphics items
        // when PageRow itself instantiates a Component. Construct the Page
        // explicitly and let PageRow adopt the actual object. No warning
        // filters or global QML logging overrides are necessary.
        // Component.createObject returns QObject to QML static analysis.
        const nextPage = sectionPageComponent.createObject(null, { "sectionId": sectionId }) as SectionPage
        if (!nextPage) {
            return false
        }
        const insertedPage = pageStack.replace(nextPage)
        if (insertedPage !== nextPage) {
            nextPage.destroy()
            return false
        }
        activeSection = sectionId
        nextPage.focusPrimary()
        // Only the decorative title accent moves. Page replacement and
        // snapshot clearing above are synchronous and never animated here.
        if (window.motionAllowed)
            navigationMotion.restart()
        return true
    }

    onNavigationRequestChanged: {
        if (navigationRequest.length > 0) {
            navigateTo(navigationRequest)
        }
    }

    pageStack.globalToolBar.style: Kirigami.ApplicationHeaderStyle.None

    globalDrawer: Kirigami.GlobalDrawer {
        handleVisible: false
        title: qsTr("KnetSentry")
        titleIcon: "security-high"
        isMenu: false
        actions: [
            Kirigami.Action {
                text: qsTr("Dashboard")
                icon.name: "view-dashboard"
                shortcut: "Ctrl+1"
                onTriggered: window.navigateTo("dashboard")
            },
            Kirigami.Action {
                text: qsTr("Assets")
                icon.name: "network-wired"
                shortcut: "Ctrl+2"
                onTriggered: window.navigateTo("assets")
            },
            Kirigami.Action {
                text: qsTr("Events")
                icon.name: "view-list-details"
                shortcut: "Ctrl+3"
                onTriggered: window.navigateTo("events")
            },
            Kirigami.Action {
                text: qsTr("Detections")
                icon.name: "security-medium"
                shortcut: "Ctrl+4"
                onTriggered: window.navigateTo("detections")
            },
            Kirigami.Action {
                text: qsTr("Alerts")
                icon.name: "dialog-warning"
                shortcut: "Ctrl+5"
                onTriggered: window.navigateTo("alerts")
            },
            Kirigami.Action {
                text: qsTr("Investigations")
                icon.name: "system-search"
                shortcut: "Ctrl+6"
                onTriggered: window.navigateTo("investigations")
            },
            Kirigami.Action {
                text: qsTr("Settings")
                icon.name: "settings-configure"
                shortcut: "Ctrl+7"
                onTriggered: window.navigateTo("settings")
            }
        ]
    }

    Component {
        id: sectionPageComponent
        SectionPage {
            timelineModel: window.timelineModel
            workspaceModel: window.workspaceModel
            dashboardModel: window.dashboardModel
            healthModel: window.healthModel
            eventModel: window.eventModel
            alertModel: window.alertModel
            searchViews: savedSearchViews
            textScale: window.effectiveTextScale
            textScalePercent: window.textScalePercent
            onTextScaleRequested: function(percent) { window.applyTextScale(percent) }
            onSearchDestinationRequested: function(destination) { window.navigateTo(destination) }
        }
    }

    pageStack.initialPage: SectionPage {
        sectionId: "dashboard"
        searchViews: savedSearchViews
        textScale: window.effectiveTextScale
        textScalePercent: window.textScalePercent
        onTextScaleRequested: function(percent) { window.applyTextScale(percent) }
        onSearchDestinationRequested: function(destination) { window.navigateTo(destination) }
        timelineModel: window.timelineModel
        workspaceModel: window.workspaceModel
        dashboardModel: window.dashboardModel
        healthModel: window.healthModel
        eventModel: window.eventModel
        alertModel: window.alertModel
    }

    NumberAnimation {
        id: navigationMotion
        target: navigationAccent
        property: "opacity"
        from: 1
        to: 0
        duration: window.motionDuration
    }
    NumberAnimation {
        id: loadingMotion
        target: loadingMarker
        property: "rotation"
        from: 0
        to: 360
        duration: 900
        loops: Animation.Infinite
        running: window.motionAllowed && window.operationPending
    }

    header: Controls.ToolBar {
        implicitHeight: Math.max(44, toolbarRow.implicitHeight + 8)
        RowLayout {
            id: toolbarRow
            anchors.fill: parent
            anchors.leftMargin: Kirigami.Units.smallSpacing
            anchors.rightMargin: Kirigami.Units.smallSpacing
            spacing: Kirigami.Units.smallSpacing
            Controls.ToolButton {
                id: navigationButton
                text: qsTr("Navigation")
                Layout.preferredWidth: designTokens.touchTarget
                Layout.preferredHeight: designTokens.touchTarget
                display: Controls.AbstractButton.IconOnly
                icon.name: "application-menu"
                icon.source: "icons/menu.svg"
                Accessible.name: text
                onClicked: window.globalDrawer.drawerOpen = !window.globalDrawer.drawerOpen
                Controls.ToolTip.visible: hovered
                Controls.ToolTip.text: text
                Rectangle {
                    anchors.bottom: parent.bottom
                    anchors.horizontalCenter: parent.horizontalCenter
                    width: parent.width / 2
                    height: 2
                    color: Kirigami.Theme.highlightColor
                    visible: navigationButton.hovered || navigationButton.activeFocus
                    Accessible.ignored: true
                }
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2
                Controls.Label {
                    text: window.activeSectionTitle
                    font.pixelSize: designTokens.sectionSize
                    Layout.fillWidth: true
                    elide: Text.ElideRight
                }
                // Reserve the same space in both motion modes.
                Item {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 2
                    Rectangle {
                        id: navigationAccent
                        width: Math.min(parent.width, 64)
                        height: parent.height
                        color: Kirigami.Theme.highlightColor
                        opacity: 0
                        visible: window.motionAllowed && navigationMotion.running
                        Accessible.ignored: true
                    }
                }
            }
            Controls.CheckBox {
                id: motionToggle
                text: qsTr("Reduce motion")
                Accessible.name: text
                checked: window.reduceMotion
                onToggled: window.reduceMotion = checked
                Controls.ToolTip.visible: hovered
                Controls.ToolTip.text: qsTr("Session only. Platform-disabled motion stays disabled.")
            }
            Item {
                id: indicator
                Layout.preferredWidth: 120
                Layout.preferredHeight: 32
                readonly property color stateColor: window.toolbarTone === 2 ? Kirigami.Theme.positiveTextColor
                    : window.toolbarTone === 1 ? Kirigami.Theme.neutralTextColor : Kirigami.Theme.negativeTextColor
                Accessible.role: Accessible.StaticText
                Accessible.name: window.daemonControl.status
                HoverHandler { id: indicatorHover }
                Controls.ToolTip.visible: indicatorHover.hovered
                Controls.ToolTip.text: window.daemonControl.status + qsTr(" — optional pulse: successful health exchange, not monitoring activity")
                Rectangle {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    width: 10; height: 10; radius: width / 2
                    color: indicator.stateColor
                }
                Item {
                    id: heartbeat
                    x: 18
                    width: 98
                    height: 24
                    anchors.verticalCenter: parent.verticalCenter
                    readonly property color lineColor: indicator.stateColor
                    readonly property bool activePulse: window.toolbarPulse && window.motionAllowed
                    // Fixed scene geometry: no raster-backed Canvas or paint context.
                    Rectangle {
                        x: 1; y: 11; width: 96; height: 2
                        color: heartbeat.lineColor
                        visible: !heartbeat.activePulse
                    }
                    Item {
                        anchors.fill: parent
                        visible: heartbeat.activePulse
                        Rectangle {
                            x: 0.60; y: 11.00
                            width: 31.80; height: 2; rotation: 0.00
                            color: heartbeat.lineColor
                            antialiasing: true
                        }
                        Rectangle {
                            x: 30.28; y: 7.50
                            width: 11.43; height: 2; rotation: -41.19
                            color: heartbeat.lineColor
                            antialiasing: true
                        }
                        Rectangle {
                            x: 35.35; y: 11.50
                            width: 18.29; height: 2; rotation: 59.04
                            color: heartbeat.lineColor
                            antialiasing: true
                        }
                        Rectangle {
                            x: 42.75; y: 10.00
                            width: 20.50; height: 2; rotation: -66.04
                            color: heartbeat.lineColor
                            antialiasing: true
                        }
                        Rectangle {
                            x: 54.20; y: 6.00
                            width: 13.61; height: 2; rotation: 51.34
                            color: heartbeat.lineColor
                            antialiasing: true
                        }
                        Rectangle {
                            x: 64.60; y: 11.00
                            width: 32.80; height: 2; rotation: 0.00
                            color: heartbeat.lineColor
                            antialiasing: true
                        }
                    }
                }
            }
            Controls.ToolButton {
                id: startButton
                text: qsTr("Start desktop-owned daemon")
                Layout.preferredWidth: designTokens.touchTarget
                Layout.preferredHeight: designTokens.touchTarget
                display: Controls.AbstractButton.IconOnly
                icon.name: "media-playback-start"
                icon.source: "icons/play.svg"
                enabled: window.daemonControl.canStart
                Accessible.name: text
                onClicked: window.daemonControl.startManager()
                Controls.ToolTip.visible: hovered
                Controls.ToolTip.text: enabled ? text : window.daemonControl.status
            }
            Controls.ToolButton {
                id: stopButton
                text: qsTr("Stop desktop-owned daemon")
                Layout.preferredWidth: designTokens.touchTarget
                Layout.preferredHeight: designTokens.touchTarget
                display: Controls.AbstractButton.IconOnly
                icon.name: "media-playback-stop"
                icon.source: "icons/stop.svg"
                enabled: window.daemonControl.canStop
                Accessible.name: text
                onClicked: window.daemonControl.stopManager()
                Controls.ToolTip.visible: hovered
                Controls.ToolTip.text: enabled ? text : window.daemonControl.status
            }
        }
    }

    footer: Controls.ToolBar {
        implicitHeight: feedbackColumn.implicitHeight + 8
        ColumnLayout {
            id: feedbackColumn
            anchors.fill: parent
            anchors.leftMargin: Kirigami.Units.largeSpacing
            anchors.rightMargin: Kirigami.Units.largeSpacing
            anchors.topMargin: 4
            anchors.bottomMargin: 4
            spacing: 2
            RowLayout {
                Layout.fillWidth: true
                Controls.Label {
                    text: qsTr("Monitoring is not active — daemon health is not security coverage")
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Controls.Label { text: qsTr("M8.7 development") }
            }
            RowLayout {
                Layout.fillWidth: true
                // Non-modal status notification: actual model text, not a
                // synthesized success notification or a transient toast queue.
                Controls.Label {
                    text: window.daemonControl.status
                    textFormat: Text.PlainText
                    Accessible.name: text
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                RowLayout {
                    id: requestFeedback
                    visible: window.operationPending
                    spacing: designTokens.spaceS
                    Rectangle {
                        id: loadingMarker
                        Layout.preferredWidth: 12
                        Layout.preferredHeight: 12
                        color: "transparent"
                        border.width: 1
                        border.color: Kirigami.Theme.textColor
                        radius: 6
                        Accessible.ignored: true
                        Rectangle {
                            width: 4
                            height: 4
                            anchors.top: parent.top
                            anchors.horizontalCenter: parent.horizontalCenter
                            color: Kirigami.Theme.textColor
                        }
                    }
                    Controls.Label {
                        id: requestLabel
                        Layout.maximumWidth: Math.max(120, window.width / 3)
                        wrapMode: Text.WordWrap
                        text: qsTr("Stored request in progress…")
                        textFormat: Text.PlainText
                        Accessible.name: text
                    }
                }
            }
        }
    }
}

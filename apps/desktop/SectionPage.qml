// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import io.github.spilledmilkfactory.KnetSentry

// Presentation-only visual language; stored event summaries require an explicitly enabled manager.
Kirigami.Page {
    id: page
    objectName: "knetSentrySectionPage"
    required property string sectionId
    required property real textScale
    required property int textScalePercent
    signal textScaleRequested(int percent)
    readonly property alias keyboardContent: scroller
    readonly property alias eventKeyboardList: eventList
    readonly property alias alertKeyboardList: alertList
    readonly property alias alertPageIndicator: alertPageIndicator
    readonly property alias notificationToggle: notificationToggle
    readonly property alias attentionToggle: attentionToggle
    readonly property alias clearHistoryControl: clearHistoryButton
    readonly property string notificationHistoryText: historyLabel.text
    readonly property alias timelineKeyboardList: timelineList
    readonly property alias textScaleControl: scaleControl
    font.pixelSize: Math.round(14 * textScale)

    // Keep the system palette when readable. A fully opaque matched
    // surface and a black/white fallback protect text from poor theme pairs.
    function linearChannel(channel: real): real {
        return channel <= 0.04045 ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4)
    }
    function luminance(value: color): real {
        return 0.2126 * linearChannel(value.r) + 0.7152 * linearChannel(value.g) + 0.0722 * linearChannel(value.b)
    }
    function readableRecordText(preferred: color, surface: color): color {
        const backgroundLight = luminance(surface)
        const textLight = luminance(preferred)
        const ratio = (Math.max(backgroundLight, textLight) + 0.05) / (Math.min(backgroundLight, textLight) + 0.05)
        if (preferred.a === 1 && ratio >= 4.5)
            return preferred
        return backgroundLight >= 0.179 ? Qt.rgba(0, 0, 0, 1) : Qt.rgba(1, 1, 1, 1)
    }
    function opaqueRecordSurface(preferred: color): color {
        return Qt.rgba(preferred.r, preferred.g, preferred.b, 1)
    }

    function focusPrimary(): void {
        scroller.forceActiveFocus(Qt.TabFocusReason)
    }

    // Only scroll for focus inside this page's content, never for popup or
    // toolbar focus. Map coordinates rather than assuming immediate parents.
    function revealKeyboardFocus(item: Item): void {
        let ancestor = item
        while (ancestor && ancestor !== content)
            ancestor = ancestor.parent
        if (!ancestor || item === content)
            return
        const position = item.mapToItem(scroller.contentItem, 0, 0)
        const top = position.y
        const bottom = top + item.height
        if (top < scroller.contentY)
            scroller.contentY = Math.max(0, top - tokens.spaceS)
        else if (bottom > scroller.contentY + scroller.height)
            scroller.contentY = Math.min(Math.max(0, scroller.contentHeight - scroller.height),
                                         Math.max(0, Math.min(top, bottom - scroller.height + tokens.spaceS)))
    }

    required property SearchViews searchViews
    signal searchDestinationRequested(string destination)
    readonly property alias eventPresetControl: eventPreset
    readonly property alias eventSaveControl: saveEventsView
    readonly property alias eventRestoreControl: restoreEventsView
    readonly property alias eventForgetControl: forgetEventsView
    readonly property alias eventSourceControl: eventSource
    readonly property alias eventCollectorControl: eventMode
    readonly property alias eventOutcomeControl: eventOutcome
    readonly property alias eventOrderControl: eventOrder
    readonly property alias alertPresetControl: alertPreset
    readonly property alias alertSaveControl: saveAlertsView
    readonly property alias alertRestoreControl: restoreAlertsView
    readonly property alias alertForgetControl: forgetAlertsView
    readonly property alias alertSeverityControl: alertSeverity
    readonly property alias searchEventsRoute: openEventsView
    readonly property alias searchAlertsRoute: openAlertsView
    readonly property alias searchTimelineRoute: openTimelineView

    function setEventFilters(collector: int, outcome: int, descending: bool): void {
        page.eventModel.clear()
        eventSource.text = ""
        eventMode.currentIndex = collector
        eventOutcome.currentIndex = outcome
        eventOrder.currentIndex = descending ? 1 : 0
    }

    function setAlertFilter(severity: int): void {
        page.alertModel.clear()
        alertSeverity.currentIndex = severity
    }
    required property TimelineModel timelineModel
    readonly property alias timelineRefreshButton: timelineRefresh
    readonly property int timelineCount: timelineList.count
    readonly property string timelineDetail: timelineDetailLabel.text
    readonly property string timelineEvidence: timelineEvidenceLabel.text
    required property WorkspaceModel workspaceModel
    readonly property alias workspaceEvidenceButton: evidencePreset
    readonly property alias workspaceSaveButton: saveWorkspace
    readonly property alias workspaceResizeControl: workspaceRatio
    readonly property bool workspaceHealthVisible: healthPanel.visible
    readonly property bool workspaceChartsVisible: chartPanel.visible
    readonly property int workspaceColumns: workspaceGrid.columns
    readonly property real workspaceOverviewWidth: overviewPanel.width
    readonly property real workspaceChartWidth: chartPanel.width
    required property DashboardModel dashboardModel
    required property ServiceHealthModel healthModel
    readonly property string dashboardEvents: dashboardEventCard.description
    readonly property string dashboardAlerts: dashboardAlertCard.description
    readonly property string dashboardDetections: dashboardDetectionCard.description
    readonly property alias dashboardRefreshButton: dashboardRefresh
    readonly property string dashboardHistogramCounts: eventHistogram.countsText
    readonly property string dashboardActivityCounts: activityChart.countsText
    readonly property string dashboardSeverityCounts: severityChart.countsText
    readonly property alias dashboardActivityFilter: activityFilterControl
    readonly property alias dashboardSeverityFilter: severityFilterControl
    required property AlertModel alertModel
    required property EventExplorerModel eventModel
    readonly property int alertCount: alertList.count
    readonly property string alertDetail: alertDetailLabel.text
    readonly property string alertEvidence: alertEvidenceLabel.text
    readonly property alias alertRefreshButton: refreshAlertsButton
    readonly property alias alertAckButton: ackAlertButton
    readonly property int eventCount: eventList.count
    readonly property string eventStatus: eventStatusLabel.text
    readonly property string eventDetail: eventDetailLabel.text
    readonly property alias eventSearchButton: searchEventsButton
    readonly property alias eventNextButton: nextEventsButton
    readonly property string displayedHealthStatus: managerCard.description
    readonly property string displayedHealthResources: resourceCard.description
    readonly property string displayedHealthErrors: errorCard.description
    readonly property string displayedHealthComponents: componentCard.description
    readonly property bool telemetryVisible: telemetryPanel.visible
    readonly property string displayedTelemetryStatus: telemetryStatusCard.description
    readonly property string displayedTelemetryCollector: telemetryCollectorCard.description
    readonly property string displayedTelemetryHealth: telemetryHealthCard.description
    readonly property string displayedTelemetryRate: telemetryRateCard.description
    readonly property string displayedTelemetryQueue: telemetryQueueCard.description
    readonly property string displayedTelemetryFailure: telemetryFailureCard.description
    readonly property bool scopeVisible: scopePanel.visible
    readonly property bool agentRosterVisible: agentPanel.visible
    readonly property string displayedAgentRegistry: agentRegistryCard.description
    readonly property string displayedApprovedAgents: approvedAgentsCard.description
    readonly property string displayedRevokedAgents: revokedAgentsCard.description
    readonly property string displayedScopeState: scopeStateCard.description
    readonly property string displayedScopeNetworks: scopeNetworksCard.description
    readonly property string displayedScopeInterfaces: scopeInterfacesCard.description
    readonly property string displayedScopeDenials: scopeDenialsCard.description
    title: sectionTitle
    DesignTokens { id: tokens; textScale: page.textScale }
    readonly property string visualSystemVersion: tokens.version
    readonly property bool compactLayout: width < tokens.compactBreakpoint * Math.max(1, page.textScale)

    readonly property string sectionTitle: {
        switch (sectionId) {
        case "dashboard": return qsTr("Dashboard")
        case "assets": return qsTr("Assets")
        case "events": return qsTr("Events")
        case "detections": return qsTr("Detections")
        case "alerts": return qsTr("Alerts")
        case "investigations": return qsTr("Investigations")
        case "settings": return qsTr("Settings")
        default: return qsTr("Unavailable")
        }
    }

    readonly property string sectionDescription: {
        switch (sectionId) {
        case "dashboard":
            return qsTr("Operational health, local observations and explicitly requested stored summaries. Live monitoring coverage remains unavailable.")
        case "assets":
            return qsTr("Inspect administrator-approved endpoint identities below. Live asset inventory and remote telemetry remain unavailable.")
        case "events":
            return qsTr("Search explicitly approved stored event summaries. Results are snapshots, not live monitoring.")
        case "detections":
            return qsTr("Deterministic detection rules and their evidence will appear here after the detection engine is implemented.")
        case "alerts":
            return qsTr("Inspect explicitly approved stored alerts and linked evidence. Live detection is unavailable.")
        case "investigations":
            return qsTr("Inspect related stored events and alerts through explicit evidence references. Incident cases and verified asset mapping remain unavailable.")
        case "settings":
            return qsTr("Inspect LAN scope and network authorization below. Changes and other system settings require future authorized management APIs.")
        default:
            return qsTr("This section is not available.")
        }
    }

    // Scroll rather than truncate or overlap at smaller GNOME/KDE window sizes.
    Flickable {
        id: scroller
        anchors.fill: parent
        contentWidth: width
        contentHeight: content.implicitHeight + tokens.spaceL * 2
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        activeFocusOnTab: true
        Accessible.name: qsTr("%1 page content").arg(page.sectionTitle)
        Keys.onPressed: function(event) {
            if (event.key === Qt.Key_PageDown) {
                scroller.contentY = Math.min(Math.max(0, scroller.contentHeight - scroller.height), scroller.contentY + scroller.height)
                event.accepted = true
            } else if (event.key === Qt.Key_PageUp) {
                scroller.contentY = Math.max(0, scroller.contentY - scroller.height)
                event.accepted = true
            }
        }
        Controls.ScrollBar.vertical: Controls.ScrollBar {}

        ColumnLayout {
            id: content
            x: tokens.spaceL
            y: tokens.spaceL
            width: Math.max(0, scroller.width - tokens.spaceL * 2)
            spacing: tokens.spaceM

            Controls.Label {
                text: qsTr("Keyboard: Tab / Shift+Tab moves focus; F6 moves to page content; Shift+F6 moves to navigation. Ctrl+1–7 opens sections. On record lists, Up / Down moves the cursor; Enter inspects the highlighted row. Page Up / Page Down scrolls page content.")
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }

            Controls.Label {
                text: page.sectionTitle
                font.pixelSize: tokens.titleSize
                font.weight: Font.Bold
                color: Kirigami.Theme.textColor
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                Accessible.role: Accessible.Heading
            }
            Controls.Label {
                text: qsTr("Local Network Security Intelligence")
                wrapMode: Text.WordWrap
                font.pixelSize: tokens.bodySize
                color: Kirigami.Theme.textColor
                Layout.fillWidth: true
            }
            StatusBadge {
                textScale: page.textScale
                label: qsTr("Monitoring unavailable")
            }
            Kirigami.InlineMessage {
                type: Kirigami.MessageType.Information
                visible: true
                text: qsTr("Not operational — local aggregate status and approved stored events and alerts may be shown; live remote telemetry is unavailable.")
                Layout.fillWidth: true
            }
            Controls.Label {
                text: page.sectionDescription
                font.pixelSize: tokens.bodySize
                color: Kirigami.Theme.textColor
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
            Controls.Label {
                text: qsTr("No devices, alerts, detections, or incidents are simulated. Service health is not evidence of network protection.")
                font.pixelSize: tokens.captionSize
                color: Kirigami.Theme.textColor
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            ColumnLayout {
                visible: page.sectionId === "dashboard" || page.sectionId === "events"
                         || page.sectionId === "alerts" || page.sectionId === "investigations"
                Layout.fillWidth: true
                spacing: tokens.spaceS
                Controls.Label {
                    text: qsTr("Evidence views — open a destination, then explicitly request its data. No record or authority is transferred.")
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                GridLayout {
                    columns: page.compactLayout ? 1 : 3
                    Layout.fillWidth: true
                    Controls.Button {
                        id: openEventsView
                        text: qsTr("Open Events")
                        enabled: page.sectionId !== "events"
                        onClicked: page.searchDestinationRequested("events")
                    }
                    Controls.Button {
                        id: openAlertsView
                        text: qsTr("Open Alerts")
                        enabled: page.sectionId !== "alerts"
                        onClicked: page.searchDestinationRequested("alerts")
                    }
                    Controls.Button {
                        id: openTimelineView
                        text: qsTr("Open Investigations")
                        enabled: page.sectionId !== "investigations"
                        onClicked: page.searchDestinationRequested("investigations")
                    }
                }
            }

            ColumnLayout {
                visible: page.sectionId === "investigations"
                Layout.fillWidth: true
                spacing: tokens.spaceS
                Controls.Label {
                    text: qsTr("Investigation timeline — stored pages")
                    font.pixelSize: tokens.sectionSize
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Controls.Label {
                    Layout.fillWidth: true
                    text: qsTr("Oldest to newest by event receiver time and alert creation time (Unix ms). Different clock semantics; not proof of causality. At most eight records per store, not an atomic or complete timeline. Asset identity is unavailable.")
                    wrapMode: Text.WordWrap
                }
                Controls.Button {
                    id: timelineRefresh
                    text: qsTr("Refresh investigation timeline")
                    enabled: page.timelineModel.configured && !page.timelineModel.busy
                    onClicked: page.timelineModel.refresh()
                }
                Controls.Label {
                    Layout.fillWidth: true
                    text: page.timelineModel.status
                    textFormat: Text.PlainText
                    wrapMode: Text.WordWrap
                }
                ListView {
                    id: timelineList
                    enabled: !page.timelineModel.busy && count > 0
                    activeFocusOnTab: enabled
                    keyNavigationEnabled: true
                    keyNavigationWraps: false
                    Accessible.role: Accessible.List
                    Accessible.name: qsTr("Investigation records")
                    Accessible.description: qsTr("Up and Down move the cursor. Enter or Space inspects the current record.")
                    function inspectCurrent(): void {
                        if (enabled && currentIndex >= 0 && currentIndex < count)
                            page.timelineModel.select(currentIndex)
                    }
                    Keys.onReturnPressed: inspectCurrent()
                    Keys.onEnterPressed: inspectCurrent()
                    Keys.onSpacePressed: inspectCurrent()
                    Keys.onUpPressed: decrementCurrentIndex()
                    Keys.onDownPressed: incrementCurrentIndex()
                    Rectangle {
                        anchors.fill: parent
                        color: "transparent"
                        border.width: 2
                        border.color: Kirigami.Theme.textColor
                        visible: timelineList.activeFocus
                        parent: timelineList
                        z: 2
                        Accessible.ignored: true
                    }
                    Layout.fillWidth: true
                    Layout.preferredHeight: 300
                    clip: true
                    model: page.timelineModel.entries
                    Controls.ScrollBar.vertical: Controls.ScrollBar {}
                    delegate: Controls.ItemDelegate {
                        id: timelineRow
                        readonly property color recordForeground: page.readableRecordText(highlighted ? palette.highlightedText : palette.windowText, recordBackground)
                        readonly property color recordBackground: page.opaqueRecordSurface(highlighted ? palette.highlight : palette.window)
                        required property int index
                        required property string modelData
                        width: timelineList.width
                        activeFocusOnTab: false
                        Accessible.name: timelineRow.modelData
                        highlighted: timelineList.currentIndex === timelineRow.index && timelineList.activeFocus
                        enabled: !page.timelineModel.busy
                        // Use a matched palette pair, independent of the style's delegate background.
                        background: Rectangle {
                            color: timelineRow.recordBackground
                            border.width: timelineRow.hovered ? 1 : 0
                            border.color: timelineRow.palette.highlight
                        }
                        contentItem: Controls.Label {
                            color: timelineRow.recordForeground
                            text: timelineRow.modelData
                            textFormat: Text.PlainText
                            wrapMode: Text.WrapAnywhere
                        }
                        onClicked: {
                            timelineList.currentIndex = timelineRow.index
                            timelineList.forceActiveFocus(Qt.MouseFocusReason)
                            timelineList.inspectCurrent()
                        }
                    }
                }
                Controls.Label {
                    id: timelineDetailLabel
                    Layout.fillWidth: true
                    text: page.timelineModel.detail
                    textFormat: Text.PlainText
                    wrapMode: Text.WrapAnywhere
                }
                Controls.Label {
                    Layout.fillWidth: true
                    text: qsTr("Related records on these pages (stored ID, authentication collector and source unit; not a verified asset link)")
                    wrapMode: Text.WordWrap
                }
                GridLayout {
                    columns: page.compactLayout ? 1 : 2
                    Layout.fillWidth: true
                    Controls.ComboBox {
                        id: timelineRelated
                        Layout.fillWidth: true
                        model: page.timelineModel.related
                        Accessible.name: qsTr("Related timeline record")
                        enabled: !page.timelineModel.busy && count > 0
                    }
                    Controls.Button {
                        text: qsTr("Open related record")
                        enabled: !page.timelineModel.busy && timelineRelated.currentIndex >= 0
                        onClicked: page.timelineModel.follow(timelineRelated.currentIndex)
                    }
                }
                GridLayout {
                    columns: page.compactLayout ? 1 : 2
                    Layout.fillWidth: true
                    Controls.ComboBox {
                        id: timelineEvidence
                        Layout.fillWidth: true
                        model: page.timelineModel.evidence
                        Accessible.name: qsTr("Selected alert evidence identifier")
                        enabled: !page.timelineModel.busy && count > 0
                    }
                    Controls.Button {
                        text: qsTr("Verify linked evidence")
                        enabled: !page.timelineModel.busy && timelineEvidence.currentIndex >= 0
                        onClicked: page.timelineModel.verifyEvidence(timelineEvidence.currentIndex)
                    }
                }
                Controls.Label {
                    id: timelineEvidenceLabel
                    Layout.fillWidth: true
                    text: page.timelineModel.evidenceDetail
                    textFormat: Text.PlainText
                    wrapMode: Text.WrapAnywhere
                }
                Controls.Label {
                    Layout.fillWidth: true
                    text: qsTr("Evidence references may be outside the returned event page. Verification is explicit and revision-bound. Snapshots expire 30 seconds after refresh; no raw evidence or incident state is exposed.")
                    wrapMode: Text.WordWrap
                }
            }

            ColumnLayout {
                visible: page.sectionId === "alerts"
                Layout.fillWidth: true
                spacing: tokens.spaceS
                Controls.Label {
                    text: qsTr("Alerts — stored detection results")
                    font.pixelSize: tokens.sectionSize
                    Layout.fillWidth: true
                }
                Controls.Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: qsTr("Presets and saved severity views change filters only. Select Refresh to query approved storage. Saved views are session-only.")
                }
                GridLayout {
                    columns: page.compactLayout ? 1 : 4
                    Layout.fillWidth: true
                    Controls.ComboBox {
                        id: alertPreset
                        displayText: qsTr("Apply preset…")
                        Layout.fillWidth: true
                        model: [qsTr("All alerts"), qsTr("Medium severity"), qsTr("High severity"), qsTr("Critical severity")]
                        Accessible.name: qsTr("Alert search preset")
                        enabled: !page.alertModel.busy
                        onActivated: function(index) {
                            switch (index) {
                            case 0: page.setAlertFilter(0); break
                            case 1: page.setAlertFilter(4); break
                            case 2: page.setAlertFilter(5); break
                            case 3: page.setAlertFilter(6); break
                            }
                        }
                    }
                    Controls.Button {
                        id: saveAlertsView
                        text: qsTr("Save severity view")
                        enabled: !page.alertModel.busy && alertSeverity.currentIndex >= 0
                        onClicked: page.searchViews.saveAlerts(alertSeverity.currentIndex)
                    }
                    Controls.Button {
                        id: restoreAlertsView
                        text: qsTr("Restore view")
                        enabled: !page.alertModel.busy && page.searchViews.alertSaved
                        onClicked: page.setAlertFilter(page.searchViews.alertSeverity)
                    }
                    Controls.Button {
                        id: forgetAlertsView
                        text: qsTr("Forget view")
                        enabled: page.searchViews.alertSaved
                        onClicked: page.searchViews.forgetAlerts()
                    }
                }
                Controls.Label {
                    Layout.fillWidth: true
                    text: page.searchViews.alertSaved ? qsTr("One severity view saved for this session.") : qsTr("No saved severity view.")
                    wrapMode: Text.WordWrap
                }
                GridLayout {
                    columns: page.compactLayout ? 1 : 3
                    Layout.fillWidth: true
                    Controls.ComboBox {
                        id: alertSeverity
                        Layout.fillWidth: true
                        model: [qsTr("All severities"), qsTr("Unspecified"), qsTr("Informational"), qsTr("Low"), qsTr("Medium"), qsTr("High"), qsTr("Critical")]
                        Accessible.name: qsTr("Alert severity filter")
                        enabled: !page.alertModel.busy
                        onActivated: page.alertModel.clear()
                    }
                    Controls.Button {
                        id: refreshAlertsButton
                        text: qsTr("Refresh / first page")
                        enabled: !page.alertModel.busy
                        onClicked: page.alertModel.search(alertSeverity.currentIndex - 1)
                    }
                    Controls.Button {
                        text: qsTr("Next page")
                        enabled: page.alertModel.more && !page.alertModel.busy
                        onClicked: page.alertModel.next()
                    }
                }
                Controls.Label {
                    Layout.fillWidth: true
                    text: page.alertModel.status
                    textFormat: Text.PlainText
                    wrapMode: Text.WordWrap
                }
                Controls.Label {
                    id: alertPageIndicator
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: page.alertModel.activePageCount < 0
                        ? qsTr("Active stored alerts on current page: unavailable")
                        : qsTr("Active stored alerts on current page: %1 (not a global total or live monitoring)").arg(page.alertModel.activePageCount)
                    Accessible.name: text
                }
                ListView {
                    id: alertList
                    enabled: !page.alertModel.busy && count > 0
                    activeFocusOnTab: enabled
                    keyNavigationEnabled: true
                    keyNavigationWraps: false
                    Accessible.role: Accessible.List
                    Accessible.name: qsTr("Stored alert records")
                    Accessible.description: qsTr("Up and Down move the cursor. Enter or Space inspects the current record.")
                    function inspectCurrent(): void {
                        if (enabled && currentIndex >= 0 && currentIndex < count)
                            page.alertModel.select(currentIndex)
                    }
                    Keys.onReturnPressed: inspectCurrent()
                    Keys.onEnterPressed: inspectCurrent()
                    Keys.onSpacePressed: inspectCurrent()
                    Keys.onUpPressed: decrementCurrentIndex()
                    Keys.onDownPressed: incrementCurrentIndex()
                    Rectangle {
                        anchors.fill: parent
                        color: "transparent"
                        border.width: 2
                        border.color: Kirigami.Theme.textColor
                        visible: alertList.activeFocus
                        parent: alertList
                        z: 2
                        Accessible.ignored: true
                    }
                    Layout.fillWidth: true
                    Layout.preferredHeight: 220
                    clip: true
                    reuseItems: true
                    model: page.alertModel
                    Controls.ScrollBar.vertical: Controls.ScrollBar {}
                    delegate: Controls.ItemDelegate {
                        id: alertRow
                        readonly property color recordForeground: page.readableRecordText(highlighted ? palette.highlightedText : palette.windowText, recordBackground)
                        readonly property color recordBackground: page.opaqueRecordSurface(highlighted ? palette.highlight : palette.window)
                        required property int index
                        required property string alertLabel
                        width: alertList.width
                        activeFocusOnTab: false
                        Accessible.name: alertRow.alertLabel
                        highlighted: alertList.currentIndex === alertRow.index && alertList.activeFocus
                        enabled: !page.alertModel.busy
                        // Use a matched palette pair, independent of the style's delegate background.
                        background: Rectangle {
                            color: alertRow.recordBackground
                            border.width: alertRow.hovered ? 1 : 0
                            border.color: alertRow.palette.highlight
                        }
                        contentItem: Controls.Label {
                            color: alertRow.recordForeground
                            text: alertRow.alertLabel
                            textFormat: Text.PlainText
                            wrapMode: Text.WrapAnywhere
                        }
                        onClicked: {
                            alertList.currentIndex = alertRow.index
                            alertList.forceActiveFocus(Qt.MouseFocusReason)
                            alertList.inspectCurrent()
                        }
                    }
                }
                Controls.Label {
                    Layout.fillWidth: true
                    id: alertDetailLabel
                    text: page.alertModel.detail.length > 0 ? page.alertModel.detail : qsTr("Select an alert to inspect its metadata and evidence links.")
                    textFormat: Text.PlainText
                    wrapMode: Text.WrapAnywhere
                }
                Controls.Button {
                    id: ackAlertButton
                    text: qsTr("Acknowledge selected alert")
                    enabled: page.alertModel.canAcknowledge
                    onClicked: page.alertModel.acknowledge()
                }
                GridLayout {
                    columns: page.compactLayout ? 1 : 2
                    Layout.fillWidth: true
                    Controls.ComboBox {
                        id: linkedEvidence
                        Layout.fillWidth: true
                        model: page.alertModel.evidence
                        Accessible.name: qsTr("Linked evidence identifier")
                        enabled: !page.alertModel.busy && count > 0
                    }
                    Controls.Button {
                        text: qsTr("Inspect linked evidence")
                        enabled: !page.alertModel.busy && linkedEvidence.currentIndex >= 0
                        onClicked: page.alertModel.inspectEvidence(linkedEvidence.currentIndex)
                    }
                }
                Controls.Label {
                    Layout.fillWidth: true
                    id: alertEvidenceLabel
                    text: page.alertModel.evidenceDetail
                    textFormat: Text.PlainText
                    wrapMode: Text.WrapAnywhere
                }
                Controls.Label {
                    Layout.fillWidth: true
                    text: qsTr("Acknowledgement is analyst disposition, not remediation. Refresh after each update. Eight alerts per page; snapshots expire after 30 seconds.")
                    wrapMode: Text.WordWrap
                }
            }

            ColumnLayout {
                visible: page.sectionId === "events"
                Layout.fillWidth: true
                spacing: tokens.spaceS
                Controls.Label {
                    text: qsTr("Event Explorer — read-only stored evidence")
                    font.pixelSize: tokens.sectionSize
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Controls.Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: qsTr("Presets and saved categorical views change filters only. Select Search to query approved storage. Exact source text is never saved; applying a view clears it.")
                }
                GridLayout {
                    columns: page.compactLayout ? 1 : 4
                    Layout.fillWidth: true
                    Controls.ComboBox {
                        id: eventPreset
                        displayText: qsTr("Apply preset…")
                        Layout.fillWidth: true
                        model: [qsTr("All events (lowest ID first)"), qsTr("Authentication failures (highest ID first)"), qsTr("Authentication successes (highest ID first)"), qsTr("Audit (highest ID first)")]
                        Accessible.name: qsTr("Event search preset")
                        enabled: !page.eventModel.busy
                        onActivated: function(index) {
                            switch (index) {
                            case 0: page.setEventFilters(0, 0, false); break
                            case 1: page.setEventFilters(2, 3, true); break
                            case 2: page.setEventFilters(2, 2, true); break
                            case 3: page.setEventFilters(3, 0, true); break
                            }
                        }
                    }
                    Controls.Button {
                        id: saveEventsView
                        text: qsTr("Save categorical view")
                        enabled: !page.eventModel.busy && eventMode.currentIndex >= 0 && eventOutcome.currentIndex >= 0
                        onClicked: page.searchViews.saveEvents(eventMode.currentIndex, eventOutcome.currentIndex, eventOrder.currentIndex === 1)
                    }
                    Controls.Button {
                        id: restoreEventsView
                        text: qsTr("Restore view")
                        enabled: !page.eventModel.busy && page.searchViews.eventSaved
                        onClicked: page.setEventFilters(page.searchViews.eventCollector, page.searchViews.eventOutcome, page.searchViews.eventDescending)
                    }
                    Controls.Button {
                        id: forgetEventsView
                        text: qsTr("Forget view")
                        enabled: page.searchViews.eventSaved
                        onClicked: page.searchViews.forgetEvents()
                    }
                }
                Controls.Label {
                    Layout.fillWidth: true
                    text: page.searchViews.eventSaved ? qsTr("One categorical view saved for this session.") : qsTr("No saved categorical view.")
                    wrapMode: Text.WordWrap
                }
                Controls.TextField {
                    id: eventSource
                    enabled: !page.eventModel.busy
                    Layout.fillWidth: true
                    maximumLength: 128
                    placeholderText: qsTr("Exact source (e.g. ssh.service), or empty for all")
                    Accessible.name: qsTr("Exact event source")
                    onTextEdited: page.eventModel.clear()
                }
                GridLayout {
                    columns: page.compactLayout ? 1 : 2
                    Layout.fillWidth: true
                    Controls.ComboBox {
                        id: eventMode
                        enabled: !page.eventModel.busy
                        Layout.fillWidth: true
                        model: [qsTr("All collectors"), qsTr("Journal"), qsTr("Authentication"), qsTr("Audit")]
                        Accessible.name: qsTr("Collector filter")
                        onActivated: page.eventModel.clear()
                    }
                    Controls.ComboBox {
                        id: eventOutcome
                        enabled: !page.eventModel.busy
                        Layout.fillWidth: true
                        model: [qsTr("All outcomes"), qsTr("Unknown"), qsTr("Success"), qsTr("Failure")]
                        Accessible.name: qsTr("Outcome filter")
                        onActivated: page.eventModel.clear()
                    }
                }
                GridLayout {
                    columns: page.compactLayout ? 1 : 3
                    Layout.fillWidth: true
                    Controls.ComboBox {
                        id: eventOrder
                        enabled: !page.eventModel.busy
                        Layout.fillWidth: true
                        model: [qsTr("ID ascending"), qsTr("ID descending")]
                        Accessible.name: qsTr("Storage identifier sort order")
                        onActivated: page.eventModel.clear()
                    }
                    Controls.Button {
                        id: searchEventsButton
                        text: qsTr("Search / first page")
                        enabled: !page.eventModel.busy
                        onClicked: page.eventModel.search(eventSource.text, eventMode.currentIndex - 1,
                                                          eventOutcome.currentIndex - 1, eventOrder.currentIndex === 1)
                    }
                    Controls.Button {
                        id: nextEventsButton
                        text: qsTr("Next page")
                        enabled: page.eventModel.more && !page.eventModel.busy
                        onClicked: page.eventModel.next()
                    }
                }
                Controls.Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                    id: eventStatusLabel
                    text: page.eventModel.status
                }
                ListView {
                    id: eventList
                    enabled: !page.eventModel.busy && count > 0
                    activeFocusOnTab: enabled
                    keyNavigationEnabled: true
                    keyNavigationWraps: false
                    Accessible.role: Accessible.List
                    Accessible.name: qsTr("Stored event records")
                    Accessible.description: qsTr("Up and Down move the cursor. Enter or Space inspects the current record.")
                    function inspectCurrent(): void {
                        if (enabled && currentIndex >= 0 && currentIndex < count)
                            page.eventModel.select(currentIndex)
                    }
                    Keys.onReturnPressed: inspectCurrent()
                    Keys.onEnterPressed: inspectCurrent()
                    Keys.onSpacePressed: inspectCurrent()
                    Keys.onUpPressed: decrementCurrentIndex()
                    Keys.onDownPressed: incrementCurrentIndex()
                    Rectangle {
                        anchors.fill: parent
                        color: "transparent"
                        border.width: 2
                        border.color: Kirigami.Theme.textColor
                        visible: eventList.activeFocus
                        parent: eventList
                        z: 2
                        Accessible.ignored: true
                    }
                    Layout.fillWidth: true
                    Layout.preferredHeight: 220
                    clip: true
                    reuseItems: true
                    model: page.eventModel
                    Controls.ScrollBar.vertical: Controls.ScrollBar {}
                    delegate: Controls.ItemDelegate {
                        id: eventRow
                        readonly property color recordForeground: page.readableRecordText(highlighted ? palette.highlightedText : palette.windowText, recordBackground)
                        readonly property color recordBackground: page.opaqueRecordSurface(highlighted ? palette.highlight : palette.window)
                        required property int index
                        required property string eventLabel
                        width: eventList.width
                        activeFocusOnTab: false
                        Accessible.name: eventRow.eventLabel
                        highlighted: eventList.currentIndex === eventRow.index && eventList.activeFocus
                        text: eventRow.eventLabel
                        // Use a matched palette pair, independent of the style's delegate background.
                        background: Rectangle {
                            color: eventRow.recordBackground
                            border.width: eventRow.hovered ? 1 : 0
                            border.color: eventRow.palette.highlight
                        }
                        contentItem: Controls.Label {
                            color: eventRow.recordForeground
                            text: eventRow.eventLabel
                            textFormat: Text.PlainText
                            wrapMode: Text.WrapAnywhere
                            verticalAlignment: Text.AlignVCenter
                        }
                        onClicked: {
                            eventList.currentIndex = eventRow.index
                            eventList.forceActiveFocus(Qt.MouseFocusReason)
                            eventList.inspectCurrent()
                        }
                    }
                }
                Controls.Label {
                    Layout.fillWidth: true
                    id: eventDetailLabel
                    text: page.eventModel.detail.length > 0 ? page.eventModel.detail : qsTr("Select a record to inspect its normalized metadata. No raw messages are exposed.")
                    textFormat: Text.PlainText
                    wrapMode: Text.WrapAnywhere
                }
                Controls.Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: qsTr("Pages hold at most eight summaries and expire after 30 seconds. IDs are admission order, not chronological order.")
                }
            }

            ColumnLayout {
                visible: page.sectionId === "dashboard"
                Layout.fillWidth: true
                spacing: tokens.spaceS
                Controls.Label {
                    text: qsTr("Analyst workspace")
                    font.pixelSize: tokens.sectionSize
                    Layout.fillWidth: true
                    Accessible.role: Accessible.Heading
                }
                GridLayout {
                    Layout.fillWidth: true
                    columns: page.compactLayout ? 1 : 3
                    Controls.Button {
                        text: qsTr("Balanced / reset")
                        onClicked: page.workspaceModel.configure(50, true, true, true)
                    }
                    Controls.Button {
                        id: evidencePreset
                        text: qsTr("Evidence focus")
                        onClicked: page.workspaceModel.configure(40, true, false, false)
                    }
                    Controls.Button {
                        text: qsTr("Operations focus")
                        onClicked: page.workspaceModel.configure(60, false, true, true)
                    }
                }
                Controls.Label {
                    text: qsTr("Overview panel width (%) — applies in wide two-panel mode")
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Controls.SpinBox {
                    id: workspaceRatio
                    from: 30
                    to: 70
                    stepSize: 5
                    value: page.workspaceModel.ratio
                    Accessible.name: qsTr("Overview panel width percent")
                    onValueModified: page.workspaceModel.configure(workspaceRatio.value, page.workspaceModel.charts, page.workspaceModel.health, page.workspaceModel.telemetry)
                }
                Controls.CheckBox {
                    id: showCharts
                    text: qsTr("Show stored visualizations")
                    checked: page.workspaceModel.charts
                    onToggled: page.workspaceModel.configure(page.workspaceModel.ratio, showCharts.checked, page.workspaceModel.health, page.workspaceModel.telemetry)
                }
                Controls.CheckBox {
                    id: showHealth
                    text: qsTr("Show detailed daemon health")
                    checked: page.workspaceModel.health
                    onToggled: page.workspaceModel.configure(page.workspaceModel.ratio, page.workspaceModel.charts, showHealth.checked, page.workspaceModel.telemetry)
                }
                Controls.CheckBox {
                    id: showTelemetry
                    text: qsTr("Show local endpoint telemetry")
                    checked: page.workspaceModel.telemetry
                    onToggled: page.workspaceModel.configure(page.workspaceModel.ratio, page.workspaceModel.charts, page.workspaceModel.health, showTelemetry.checked)
                }
                Controls.Button {
                    id: saveWorkspace
                    text: qsTr("Save workspace layout")
                    onClicked: page.workspaceModel.save()
                }
                Controls.Label {
                    text: page.workspaceModel.status
                    font.weight: Font.DemiBold
                    textFormat: Text.PlainText
                    Accessible.name: text
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
            }

            GridLayout {
                id: workspaceGrid
                visible: page.sectionId === "dashboard"
                Layout.fillWidth: true
                columns: content.width >= 1000 * Math.max(1, page.textScalePercent / 100.0) && page.workspaceModel.charts ? 2 : 1
                columnSpacing: tokens.spaceM
                rowSpacing: tokens.spaceM
                ColumnLayout {
                    id: overviewPanel
                    Layout.fillWidth: true
                    Layout.minimumWidth: 0
                    Layout.alignment: Qt.AlignTop
                    Layout.preferredWidth: workspaceGrid.columns === 2 ? (content.width - tokens.spaceM) * page.workspaceModel.ratio / 100 : content.width
                    spacing: tokens.spaceM
                    Controls.Label {
                        text: qsTr("SOC overview")
                        font.pixelSize: tokens.sectionSize
                        font.weight: Font.DemiBold
                        Layout.fillWidth: true
                        Accessible.role: Accessible.Heading
                    }
                    GridLayout {
                        Layout.fillWidth: true
                        columns: page.compactLayout || workspaceGrid.columns === 2 ? 1 : 2
                        columnSpacing: tokens.spaceM
                        rowSpacing: tokens.spaceM
                        SurfaceCard {
                            textScale: page.textScale
                            Layout.fillWidth: true
                            heading: qsTr("Security status")
                            description: qsTr("Monitoring unavailable — security posture unknown. No safety verdict.")
                        }
                        SurfaceCard {
                            textScale: page.textScale
                            Layout.fillWidth: true
                            heading: qsTr("Asset coverage and registry")
                            description: page.healthModel.dashboardRegistry
                        }
                        SurfaceCard {
                            textScale: page.textScale
                            id: dashboardEventCard
                            Layout.fillWidth: true
                            heading: qsTr("Stored event activity — latest admission page")
                            description: page.dashboardModel.eventSummary
                        }
                        SurfaceCard {
                            textScale: page.textScale
                            id: dashboardAlertCard
                            Layout.fillWidth: true
                            heading: qsTr("Active stored alerts — first page")
                            description: page.dashboardModel.alertSummary
                        }
                        SurfaceCard {
                            textScale: page.textScale
                            id: dashboardDetectionCard
                            Layout.fillWidth: true
                            Layout.columnSpan: page.compactLayout || workspaceGrid.columns === 2 ? 1 : 2
                            heading: qsTr("Stored detection summary — first alert page")
                            description: page.dashboardModel.detectionSummary
                        }
                    }
                    Controls.Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        text: qsTr("Stored summaries require explicit manager authorization and a manual refresh. Each page holds at most eight records; counts are not global totals, incident counts or live rates. Snapshots expire within 30 seconds and are cleared when leaving Dashboard.")
                    }
                    Controls.Button {
                        id: dashboardRefresh
                        text: qsTr("Refresh stored summaries")
                        enabled: page.sectionId === "dashboard" && page.dashboardModel.configured && !page.dashboardModel.busy
                        onClicked: page.dashboardModel.refresh()
                    }
                }
                ColumnLayout {
                    id: chartPanel
                    visible: page.workspaceModel.charts
                    Layout.fillWidth: true
                    Layout.minimumWidth: 0
                    Layout.alignment: Qt.AlignTop
                    Layout.preferredWidth: workspaceGrid.columns === 2 ? (content.width - tokens.spaceM) * (100 - page.workspaceModel.ratio) / 100 : content.width
                    spacing: tokens.spaceM
                    Controls.Label {
                        Layout.fillWidth: true
                        text: qsTr("Stored security visualizations")
                        font.pixelSize: tokens.sectionSize
                        font.weight: Font.DemiBold
                        Accessible.role: Accessible.Heading
                    }
                    Controls.Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        text: qsTr("Counts from the same returned pages only; each bar has a fixed scale of 0–8 records. Filters affect only these charts, not the stores or other views.")
                    }
                    SnapshotBars {
                        id: eventHistogram
                        Layout.fillWidth: true
                        heading: qsTr("Event histogram — outcome")
                        labels: [qsTr("Unknown"), qsTr("Success"), qsTr("Failure")]
                        values: page.dashboardModel.eventHistogram
                    }
                    Controls.Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        text: qsTr("Activity by receiver age relative to the newest receiver timestamp on this page. Oldest bin is open-ended; these are counts, not rates or a continuous timeline.")
                    }
                    Controls.ComboBox {
                        id: activityFilterControl
                        Layout.fillWidth: true
                        Accessible.name: qsTr("Activity outcome filter")
                        enabled: activityChart.available
                        model: [qsTr("All outcomes"), qsTr("Unknown"), qsTr("Success"), qsTr("Failure")]
                        currentIndex: page.dashboardModel.activityFilter
                        onActivated: function(index) { page.dashboardModel.activityFilter = index }
                    }
                    SnapshotBars {
                        id: activityChart
                        Layout.fillWidth: true
                        heading: qsTr("Receiver activity trend — older to newer")
                        labels: [qsTr("3 s or more earlier"), qsTr("2 to <3 s earlier"), qsTr("1 to <2 s earlier"), qsTr("Less than 1 s earlier")]
                        values: page.dashboardModel.activityCounts
                    }
                    Controls.ComboBox {
                        id: severityFilterControl
                        Layout.fillWidth: true
                        Accessible.name: qsTr("Alert lifecycle filter")
                        enabled: severityChart.available
                        model: [qsTr("All stored alerts"), qsTr("Active only (open and acknowledged)")]
                        currentIndex: page.dashboardModel.severityFilter
                        onActivated: function(index) { page.dashboardModel.severityFilter = index }
                    }
                    SnapshotBars {
                        id: severityChart
                        Layout.fillWidth: true
                        heading: qsTr("Stored alert severity distribution")
                        labels: [qsTr("Unspecified"), qsTr("Informational"), qsTr("Low"), qsTr("Medium"), qsTr("High"), qsTr("Critical")]
                        values: page.dashboardModel.severityCounts
                    }
                }
            }

            ColumnLayout {
                id: healthPanel
                visible: page.sectionId === "dashboard" && page.workspaceModel.health
                Layout.fillWidth: true
                spacing: tokens.spaceM
                Controls.Label {
                    text: qsTr("Management daemon health")
                    font.pixelSize: tokens.sectionSize
                    font.weight: Font.DemiBold
                    Layout.fillWidth: true
                    Accessible.role: Accessible.Heading
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: managerCard
                    objectName: "managerHealthCard"
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    heading: qsTr("Daemon status")
                    description: page.healthModel.status
                }
                Controls.Label {
                    text: qsTr("Read-only snapshot; refreshed every 30 seconds when configured. A disconnected service has no current health values.")
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
                SurfaceCard {
                    textScale: page.textScale
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    id: componentCard
                    heading: qsTr("Component health")
                    description: page.healthModel.components
                }
                SurfaceCard {
                    textScale: page.textScale
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    id: resourceCard
                    heading: qsTr("Process resources")
                    description: page.healthModel.resources
                }
                SurfaceCard {
                    textScale: page.textScale
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    id: errorCard
                    heading: qsTr("Operational counters — not incidents")
                    description: page.healthModel.errors
                }
            }

            ColumnLayout {
                id: telemetryPanel
                visible: page.sectionId === "assets" || (page.sectionId === "dashboard" && page.workspaceModel.telemetry)
                Layout.fillWidth: true
                spacing: tokens.spaceM
                Controls.Label {
                    text: qsTr("Local Endpoint Telemetry Status")
                    font.pixelSize: tokens.sectionSize
                    font.weight: Font.DemiBold
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    Accessible.role: Accessible.Heading
                }
                Kirigami.InlineMessage {
                    visible: true
                    type: Kirigami.MessageType.Information
                    text: qsTr("One explicitly attached local agent report stream. Not tied to enrolled identities; no operational delivery or network coverage is established.")
                    Layout.fillWidth: true
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: telemetryStatusCard
                    Layout.fillWidth: true
                    heading: qsTr("Local report stream")
                    description: page.healthModel.telemetryStatus
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: telemetryCollectorCard
                    Layout.fillWidth: true
                    heading: qsTr("Selected collector")
                    description: page.healthModel.telemetryCollector
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: telemetryHealthCard
                    Layout.fillWidth: true
                    heading: qsTr("Collection health")
                    description: page.healthModel.telemetryHealth
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: telemetryRateCard
                    Layout.fillWidth: true
                    heading: qsTr("Local observation rate — not incidents")
                    description: page.healthModel.telemetryRate
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: telemetryQueueCard
                    Layout.fillWidth: true
                    heading: qsTr("Offline telemetry buffer")
                    description: page.healthModel.telemetryQueue
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: telemetryFailureCard
                    Layout.fillWidth: true
                    heading: qsTr("Collection failure status")
                    description: page.healthModel.telemetryFailure
                }
            }

            ColumnLayout {
                id: agentPanel
                visible: page.sectionId === "assets"
                Layout.fillWidth: true
                spacing: tokens.spaceM
                Controls.Label {
                    text: qsTr("Enrollment & Agent Management")
                    font.pixelSize: tokens.sectionSize
                    font.weight: Font.DemiBold
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    Accessible.role: Accessible.Heading
                }
                Kirigami.InlineMessage {
                    visible: true
                    type: Kirigami.MessageType.Information
                    text: qsTr("Read-only inspection of the explicitly selected manager registry. Approval is not certificate validity, connection health or monitoring authorization.")
                    Layout.fillWidth: true
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: agentRegistryCard
                    Layout.fillWidth: true
                    heading: qsTr("Enrollment registry")
                    description: page.healthModel.agentRegistryStatus
                }
                SurfaceCard {
                    textScale: page.textScale
                    Layout.fillWidth: true
                    heading: qsTr("Pending enrollments")
                    description: qsTr("Unavailable — no enrollment request collection is active. Unknown agents are not automatically enrolled.")
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: approvedAgentsCard
                    Layout.fillWidth: true
                    heading: qsTr("Approved endpoint identities")
                    description: page.healthModel.approvedAgents
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: revokedAgentsCard
                    Layout.fillWidth: true
                    heading: qsTr("Revoked endpoint identities")
                    description: page.healthModel.revokedAgents
                }
                SurfaceCard {
                    textScale: page.textScale
                    Layout.fillWidth: true
                    heading: qsTr("Certificate status")
                    description: qsTr("Unavailable — registry approval does not establish current certificate validity. No live certificate observations are published.")
                }
                SurfaceCard {
                    textScale: page.textScale
                    Layout.fillWidth: true
                    heading: qsTr("Agent connection health")
                    description: qsTr("Unavailable — the manager does not host operational agent sessions. The global daemon heartbeat is local service health only.")
                }
                SurfaceCard {
                    textScale: page.textScale
                    Layout.fillWidth: true
                    heading: qsTr("Administrative actions")
                    description: qsTr("Approval, rotation and revocation require the authorized offline enrollment tool. This desktop connection has read-only authority; no administrative actions are available here.")
                }
            }

            ColumnLayout {
                id: scopePanel
                visible: page.sectionId === "settings"
                Layout.fillWidth: true
                spacing: tokens.spaceM
                Controls.Label {
                    text: qsTr("LAN Scope & Network Authorization")
                    font.pixelSize: tokens.sectionSize
                    font.weight: Font.DemiBold
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    Accessible.role: Accessible.Heading
                }
                Kirigami.InlineMessage {
                    visible: true
                    type: Kirigami.MessageType.Information
                    text: qsTr("Read-only inspection. Default-deny policy is implemented; no operational network scope can be activated here.")
                    Layout.fillWidth: true
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: scopeStateCard
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    heading: qsTr("Policy state")
                    description: page.healthModel.scopeState
                    iconName: "security-high"
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: scopeNetworksCard
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    heading: qsTr("Approved networks and endpoints")
                    description: page.healthModel.scopeNetworks
                    iconName: "network-wired"
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: scopeInterfacesCard
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    heading: qsTr("Approved interfaces")
                    description: page.healthModel.scopeInterfaces
                    iconName: "network-wired"
                }
                SurfaceCard {
                    textScale: page.textScale
                    id: scopeDenialsCard
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    heading: qsTr("Denied-connection diagnostics")
                    description: page.healthModel.scopeDenials
                    iconName: "dialog-information"
                }
                SurfaceCard {
                    textScale: page.textScale
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    heading: qsTr("Policy requirements — not active approvals")
                    description: qsTr("Agent transport requires explicit numeric IPv4/IPv6 scope, identity, TCP port, approved interface and current verified direct-route evidence. Passive monitoring and public intelligence have separate authorization requirements. A healthy daemon is not proof of firewall enforcement or monitoring coverage.")
                    iconName: "dialog-information"
                }
                Controls.Label {
                    text: qsTr("Runtime information uses the existing verified health snapshot (refreshed every 30 seconds). No configuration writes, network discovery or firewall changes are available from this page.")
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
            }

            Flow {
                id: cards
                spacing: tokens.spaceM
                Layout.fillWidth: true
                Layout.preferredHeight: childrenRect.height
                SurfaceCard {
                    textScale: page.textScale
                    width: cards.width > tokens.compactBreakpoint
                           ? (cards.width - cards.spacing) / 2 : cards.width
                    heading: qsTr("Implementation status")
                    description: qsTr("Development collectors and storage are implemented. Live ingestion and detection remain unavailable. Manager health is available through local IPC.")
                    iconName: "dialog-information"
                }
                SurfaceCard {
                    textScale: page.textScale
                    width: cards.width > tokens.compactBreakpoint
                           ? (cards.width - cards.spacing) / 2 : cards.width
                    heading: qsTr("Monitoring coverage")
                    description: qsTr("Unavailable. Missing telemetry is not evidence of a safe network or an absence of threats.")
                    iconName: "network-disconnect"
                }
            }

            ColumnLayout {
                visible: page.sectionId === "settings"
                Layout.fillWidth: true
                spacing: tokens.spaceS
                Controls.Label {
                    text: qsTr("Notifications — current session")
                    font.pixelSize: tokens.sectionSize
                    font.weight: Font.DemiBold
                    Accessible.role: Accessible.Heading
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Controls.CheckBox {
                    id: notificationToggle
                    text: qsTr("Keep session notification history")
                    Accessible.name: text
                    checked: page.alertModel.notificationsEnabled
                    onToggled: page.alertModel.notificationsEnabled = checked
                    Layout.fillWidth: true
                }
                Controls.CheckBox {
                    id: attentionToggle
                    text: qsTr("Allow desktop window attention")
                    Accessible.name: text
                    checked: page.alertModel.attentionEnabled
                    onToggled: page.alertModel.attentionEnabled = checked
                    Layout.fillWidth: true
                }
                Controls.Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: qsTr("Both are off by default and reset at restart. Window attention is optional and platform-dependent; no desktop notification content is sent. History holds at most eight generic notices, not alert results or evidence. Disabling history clears it.")
                }
                Controls.Label {
                    id: historyLabel
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                    text: page.alertModel.notificationCount > 0 ? page.alertModel.notificationHistoryText : qsTr("No retained notices.")
                    Accessible.name: text
                }
                Controls.Button {
                    id: clearHistoryButton
                    text: qsTr("Clear notification history")
                    enabled: page.alertModel.notificationCount > 0
                    onClicked: page.alertModel.clearNotificationHistory()
                }
                Controls.Label {
                    text: qsTr("Accessibility — text size")
                    font.pixelSize: tokens.sectionSize
                    font.weight: Font.DemiBold
                    Accessible.role: Accessible.Heading
                    Layout.fillWidth: true
                }
                Controls.Label {
                    text: qsTr("Magnify the startup platform font for this session. Reduced motion remains available in the toolbar.")
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Controls.ComboBox {
                    id: scaleControl
                    Accessible.name: qsTr("Application text size")
                    Layout.fillWidth: true
                    model: [qsTr("100% — platform default"), qsTr("125%"), qsTr("150%")]
                    currentIndex: page.textScalePercent === 150 ? 2 : page.textScalePercent === 125 ? 1 : 0
                    onActivated: function(index) { page.textScaleRequested(index === 2 ? 150 : index === 1 ? 125 : 100) }
                }
                Controls.Label {
                    text: qsTr("Visual system reference — examples only")
                    font.pixelSize: tokens.sectionSize
                    font.weight: Font.DemiBold
                    Layout.fillWidth: true
                }
                Controls.Label {
                    text: qsTr("The application follows the active Qt/KDE system palette, including light and dark appearance. These are severity color samples, not real alerts.")
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
                Flow {
                    id: paletteSamples
                    spacing: tokens.spaceS
                    Layout.fillWidth: true
                    Layout.preferredHeight: childrenRect.height
                    SeverityBadge { textScale: page.textScale; level: "critical" }
                    SeverityBadge { textScale: page.textScale; level: "high" }
                    SeverityBadge { textScale: page.textScale; level: "medium" }
                    SeverityBadge { textScale: page.textScale; level: "low" }
                    SeverityBadge { textScale: page.textScale; level: "unknown" }
                }
                Controls.Label {
                    text: qsTr("Severity is distinct from monitoring availability and source confidence. No alerts are loaded.")
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
            }

            Controls.Label {
                text: qsTr("M1.5 · Visual design system foundation")
                font.pixelSize: tokens.captionSize
                color: Kirigami.Theme.textColor
                Layout.fillWidth: true
                topPadding: tokens.spaceL
            }
        }
    }
}

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
    DesignTokens { id: tokens }
    readonly property string visualSystemVersion: tokens.version
    readonly property bool compactLayout: width < tokens.compactBreakpoint

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
            return qsTr("Investigation timelines, incident cases, and preserved evidence will appear here after the incident workflow is implemented.")
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
        Controls.ScrollBar.vertical: Controls.ScrollBar {}

        ColumnLayout {
            id: content
            x: tokens.spaceL
            y: tokens.spaceL
            width: Math.max(0, scroller.width - tokens.spaceL * 2)
            spacing: tokens.spaceM

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
                font.pixelSize: tokens.bodySize
                color: Kirigami.Theme.textColor
                Layout.fillWidth: true
            }
            StatusBadge {
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
                visible: page.sectionId === "alerts"
                Layout.fillWidth: true
                spacing: tokens.spaceS
                Controls.Label {
                    text: qsTr("Alerts — stored detection results")
                    font.pixelSize: tokens.sectionSize
                    Layout.fillWidth: true
                }
                RowLayout {
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
                ListView {
                    id: alertList
                    Layout.fillWidth: true
                    Layout.preferredHeight: 220
                    clip: true
                    reuseItems: true
                    model: page.alertModel
                    Controls.ScrollBar.vertical: Controls.ScrollBar {}
                    delegate: Controls.ItemDelegate {
                        id: alertRow
                        required property int index
                        required property string alertLabel
                        width: alertList.width
                        enabled: !page.alertModel.busy
                        contentItem: Controls.Label {
                            text: alertRow.alertLabel
                            textFormat: Text.PlainText
                            elide: Text.ElideRight
                        }
                        onClicked: page.alertModel.select(alertRow.index)
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
                RowLayout {
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
                Controls.TextField {
                    id: eventSource
                    Layout.fillWidth: true
                    maximumLength: 128
                    placeholderText: qsTr("Exact source (e.g. ssh.service), or empty for all")
                    Accessible.name: qsTr("Exact event source")
                    onTextEdited: page.eventModel.clear()
                }
                RowLayout {
                    Layout.fillWidth: true
                    Controls.ComboBox {
                        id: eventMode
                        Layout.fillWidth: true
                        model: [qsTr("All collectors"), qsTr("Journal"), qsTr("Authentication"), qsTr("Audit")]
                        Accessible.name: qsTr("Collector filter")
                        onActivated: page.eventModel.clear()
                    }
                    Controls.ComboBox {
                        id: eventOutcome
                        Layout.fillWidth: true
                        model: [qsTr("All outcomes"), qsTr("Unknown"), qsTr("Success"), qsTr("Failure")]
                        Accessible.name: qsTr("Outcome filter")
                        onActivated: page.eventModel.clear()
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    Controls.ComboBox {
                        id: eventOrder
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
                    Layout.fillWidth: true
                    Layout.preferredHeight: 220
                    clip: true
                    reuseItems: true
                    model: page.eventModel
                    Controls.ScrollBar.vertical: Controls.ScrollBar {}
                    delegate: Controls.ItemDelegate {
                        id: eventRow
                        required property int index
                        required property string eventLabel
                        width: eventList.width
                        text: eventRow.eventLabel
                        contentItem: Controls.Label {
                            text: eventRow.eventLabel
                            textFormat: Text.PlainText
                            elide: Text.ElideRight
                            verticalAlignment: Text.AlignVCenter
                        }
                        onClicked: page.eventModel.select(eventRow.index)
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
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
            }

            GridLayout {
                id: workspaceGrid
                visible: page.sectionId === "dashboard"
                Layout.fillWidth: true
                columns: content.width >= 1000 && page.workspaceModel.charts ? 2 : 1
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
                            Layout.fillWidth: true
                            heading: qsTr("Security status")
                            description: qsTr("Monitoring unavailable — security posture unknown. No safety verdict.")
                        }
                        SurfaceCard {
                            Layout.fillWidth: true
                            heading: qsTr("Asset coverage and registry")
                            description: page.healthModel.dashboardRegistry
                        }
                        SurfaceCard {
                            id: dashboardEventCard
                            Layout.fillWidth: true
                            heading: qsTr("Stored event activity — latest admission page")
                            description: page.dashboardModel.eventSummary
                        }
                        SurfaceCard {
                            id: dashboardAlertCard
                            Layout.fillWidth: true
                            heading: qsTr("Active stored alerts — first page")
                            description: page.dashboardModel.alertSummary
                        }
                        SurfaceCard {
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
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    id: componentCard
                    heading: qsTr("Component health")
                    description: page.healthModel.components
                }
                SurfaceCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    id: resourceCard
                    heading: qsTr("Process resources")
                    description: page.healthModel.resources
                }
                SurfaceCard {
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
                    id: telemetryStatusCard
                    Layout.fillWidth: true
                    heading: qsTr("Local report stream")
                    description: page.healthModel.telemetryStatus
                }
                SurfaceCard {
                    id: telemetryCollectorCard
                    Layout.fillWidth: true
                    heading: qsTr("Selected collector")
                    description: page.healthModel.telemetryCollector
                }
                SurfaceCard {
                    id: telemetryHealthCard
                    Layout.fillWidth: true
                    heading: qsTr("Collection health")
                    description: page.healthModel.telemetryHealth
                }
                SurfaceCard {
                    id: telemetryRateCard
                    Layout.fillWidth: true
                    heading: qsTr("Local observation rate — not incidents")
                    description: page.healthModel.telemetryRate
                }
                SurfaceCard {
                    id: telemetryQueueCard
                    Layout.fillWidth: true
                    heading: qsTr("Offline telemetry buffer")
                    description: page.healthModel.telemetryQueue
                }
                SurfaceCard {
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
                    id: agentRegistryCard
                    Layout.fillWidth: true
                    heading: qsTr("Enrollment registry")
                    description: page.healthModel.agentRegistryStatus
                }
                SurfaceCard {
                    Layout.fillWidth: true
                    heading: qsTr("Pending enrollments")
                    description: qsTr("Unavailable — no enrollment request collection is active. Unknown agents are not automatically enrolled.")
                }
                SurfaceCard {
                    id: approvedAgentsCard
                    Layout.fillWidth: true
                    heading: qsTr("Approved endpoint identities")
                    description: page.healthModel.approvedAgents
                }
                SurfaceCard {
                    id: revokedAgentsCard
                    Layout.fillWidth: true
                    heading: qsTr("Revoked endpoint identities")
                    description: page.healthModel.revokedAgents
                }
                SurfaceCard {
                    Layout.fillWidth: true
                    heading: qsTr("Certificate status")
                    description: qsTr("Unavailable — registry approval does not establish current certificate validity. No live certificate observations are published.")
                }
                SurfaceCard {
                    Layout.fillWidth: true
                    heading: qsTr("Agent connection health")
                    description: qsTr("Unavailable — the manager does not host operational agent sessions. The global daemon heartbeat is local service health only.")
                }
                SurfaceCard {
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
                    id: scopeStateCard
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    heading: qsTr("Policy state")
                    description: page.healthModel.scopeState
                    iconName: "security-high"
                }
                SurfaceCard {
                    id: scopeNetworksCard
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    heading: qsTr("Approved networks and endpoints")
                    description: page.healthModel.scopeNetworks
                    iconName: "network-wired"
                }
                SurfaceCard {
                    id: scopeInterfacesCard
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    heading: qsTr("Approved interfaces")
                    description: page.healthModel.scopeInterfaces
                    iconName: "network-wired"
                }
                SurfaceCard {
                    id: scopeDenialsCard
                    Layout.fillWidth: true
                    Layout.preferredHeight: implicitHeight
                    heading: qsTr("Denied-connection diagnostics")
                    description: page.healthModel.scopeDenials
                    iconName: "dialog-information"
                }
                SurfaceCard {
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
                    width: cards.width > tokens.compactBreakpoint
                           ? (cards.width - cards.spacing) / 2 : cards.width
                    heading: qsTr("Implementation status")
                    description: qsTr("Development collectors and storage are implemented. Live ingestion and detection remain unavailable. Manager health is available through local IPC.")
                    iconName: "dialog-information"
                }
                SurfaceCard {
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
                    SeverityBadge { level: "critical" }
                    SeverityBadge { level: "high" }
                    SeverityBadge { level: "medium" }
                    SeverityBadge { level: "low" }
                    SeverityBadge { level: "unknown" }
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

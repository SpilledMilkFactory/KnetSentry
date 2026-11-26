// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import io.github.spilledmilkfactory.KnetSentry

// M1.5: presentation-only visual language. No device, event or alert models.
Kirigami.Page {
    id: page
    objectName: "knetSentrySectionPage"
    required property string sectionId
    required property ServiceHealthModel healthModel
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
            return qsTr("Management daemon health is shown below. Monitoring coverage and security activity remain unavailable.")
        case "assets":
            return qsTr("Inspect administrator-approved endpoint identities below. Live asset inventory and remote telemetry remain unavailable.")
        case "events":
            return qsTr("Validated security-event records and search controls will appear here after the ingestion and storage pipeline is implemented.")
        case "detections":
            return qsTr("Deterministic detection rules and their evidence will appear here after the detection engine is implemented.")
        case "alerts":
            return qsTr("Verified security findings and alert triage will appear here when detection and alert management are implemented.")
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
                text: qsTr("Not operational — local aggregate collector status may be shown; remote telemetry and security events are not displayed.")
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
                visible: page.sectionId === "dashboard"
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
                visible: page.sectionId === "assets" || page.sectionId === "dashboard"
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
                    description: qsTr("Collectors, event storage and detection are not implemented. Manager health is available through explicitly configured local IPC.")
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

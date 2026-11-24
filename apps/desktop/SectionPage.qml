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
            return qsTr("Authorized LAN devices, including agentless IoT equipment, will appear here when asset inventory and telemetry are implemented.")
        case "events":
            return qsTr("Validated security-event records and search controls will appear here after the ingestion and storage pipeline is implemented.")
        case "detections":
            return qsTr("Deterministic detection rules and their evidence will appear here after the detection engine is implemented.")
        case "alerts":
            return qsTr("Verified security findings and alert triage will appear here when detection and alert management are implemented.")
        case "investigations":
            return qsTr("Investigation timelines, incident cases, and preserved evidence will appear here after the incident workflow is implemented.")
        case "settings":
            return qsTr("Authorized system settings, including future raw-event and database storage locations, will appear here after management APIs exist.")
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
                text: qsTr("Not operational — no security telemetry is being collected or displayed.")
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

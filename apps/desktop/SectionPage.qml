// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

// M1.4: seven intentionally non-operational top-level destinations.
// Future milestones will replace this shell content with authorized IPC data.
Kirigami.Page {
    id: page
    objectName: "knetSentrySectionPage"
    required property string sectionId
    title: sectionTitle

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
            return qsTr("An overview of monitoring coverage, system health, and security activity will appear here when the relevant services exist.")
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

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Kirigami.Units.largeSpacing
        spacing: Kirigami.Units.largeSpacing

        Controls.Label {
            text: page.sectionTitle
            font.pixelSize: 28
            font.bold: true
            Layout.fillWidth: true
        }

        Controls.Label {
            text: qsTr("Local Network Security Intelligence")
            Layout.fillWidth: true
        }

        Kirigami.InlineMessage {
            type: Kirigami.MessageType.Information
            visible: true
            text: qsTr("Not operational — no security telemetry is being collected or displayed.")
            Layout.fillWidth: true
        }

        Controls.Label {
            text: page.sectionDescription
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        Controls.Label {
            text: qsTr("This is an application-shell preview. No devices, alerts, detections, or incidents are simulated.")
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        Item { Layout.fillHeight: true }

        Controls.Label {
            text: qsTr("M1.4 · Primary navigation foundation")
            Layout.fillWidth: true
        }
    }
}

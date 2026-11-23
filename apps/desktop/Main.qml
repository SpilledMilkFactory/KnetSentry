// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

Kirigami.ApplicationWindow {
    id: window
    objectName: "knetSentryMainWindow"
    title: qsTr("KnetSentry — Desktop Foundation")
    width: 960
    height: 620
    minimumWidth: 640
    minimumHeight: 440
    visible: true

    pageStack.initialPage: Kirigami.Page {
        title: qsTr("Overview")

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: Kirigami.Units.largeSpacing
            spacing: Kirigami.Units.largeSpacing

            Controls.Label {
                text: qsTr("KnetSentry")
                font.pixelSize: 30
                font.bold: true
                Layout.fillWidth: true
            }

            Controls.Label {
                text: qsTr("Local Network Security Intelligence")
                Layout.fillWidth: true
            }

            Kirigami.InlineMessage {
                visible: true
                type: Kirigami.MessageType.Information
                text: qsTr("Desktop foundation only — monitoring is not active.")
                Layout.fillWidth: true
            }

            Controls.Label {
                text: qsTr("The Qt 6 and Kirigami interface is initialized. Network sensors, endpoint agents, detections, and incident management are not implemented yet.")
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Item { Layout.fillHeight: true }

            Controls.Label {
                text: qsTr("M1.3 · Application foundation")
                Layout.fillWidth: true
            }
        }
    }
}

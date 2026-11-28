// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

// Theme-aware informational card; never implies availability or live readings.
Rectangle {
    id: card
    property real textScale: 1.0
    DesignTokens { id: tokens; textScale: card.textScale }
    property string heading: ""
    property string description: ""
    property string iconName: "dialog-information"
    implicitHeight: cardContents.implicitHeight + tokens.spaceL * 2
    radius: tokens.radiusM
    Kirigami.Theme.colorSet: Kirigami.Theme.View
    Kirigami.Theme.inherit: false
    color: Kirigami.Theme.backgroundColor
    border.width: 1
    border.color: Qt.rgba(Kirigami.Theme.textColor.r,
                          Kirigami.Theme.textColor.g,
                          Kirigami.Theme.textColor.b, 0.20)

    ColumnLayout {
        id: cardContents
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: tokens.spaceL
        spacing: tokens.spaceS
        RowLayout {
            spacing: tokens.spaceS
            Kirigami.Icon {
                source: card.iconName
                Layout.preferredWidth: 22
                Layout.preferredHeight: 22
                Accessible.ignored: true
            }
            Controls.Label {
                text: card.heading
                color: Kirigami.Theme.textColor
                font.pixelSize: tokens.sectionSize
                font.weight: Font.DemiBold
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
        }
        Controls.Label {
            text: card.description
            color: Kirigami.Theme.textColor
            font.pixelSize: tokens.bodySize
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }
    }
}

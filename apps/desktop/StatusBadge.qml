// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

// Availability is explicitly NOT threat severity.
Rectangle {
    id: badge
    property real textScale: 1.0
    DesignTokens { id: tokens; textScale: badge.textScale }
    property string label: qsTr("Not operational")
    implicitWidth: badgeRow.implicitWidth + tokens.spaceM * 2
    implicitHeight: Math.max(tokens.touchTarget, badgeRow.implicitHeight + tokens.spaceS * 2)
    radius: tokens.radiusS
    color: Kirigami.Theme.backgroundColor
    border.color: Kirigami.Theme.highlightColor
    border.width: 1
    Accessible.role: Accessible.StaticText
    Accessible.name: badge.label

    RowLayout {
        id: badgeRow
        anchors.centerIn: parent
        spacing: tokens.spaceS
        Rectangle {
            implicitWidth: 9; implicitHeight: 9; radius: width / 2
            color: Kirigami.Theme.highlightColor
            Layout.alignment: Qt.AlignVCenter
        }
        Controls.Label {
            text: badge.label
            font.pixelSize: tokens.captionSize
            font.weight: Font.DemiBold
            color: Kirigami.Theme.textColor
        }
    }
}

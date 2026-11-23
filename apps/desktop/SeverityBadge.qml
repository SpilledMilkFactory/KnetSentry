// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls as Controls
import org.kde.kirigami as Kirigami

// Only for explicit severity levels. Settings shows sample tokens, not alerts.
Rectangle {
    id: badge
    DesignTokens { id: tokens }
    property string level: "unknown"
    readonly property string displayLabel: {
        switch (level) {
        case "critical": return qsTr("Critical")
        case "high": return qsTr("High")
        case "medium": return qsTr("Medium")
        case "low": return qsTr("Low")
        case "unknown": return qsTr("Unknown")
        default: return qsTr("Unknown")
        }
    }
    readonly property color fillColor: {
        switch (level) {
        case "critical": return tokens.criticalBackground
        case "high": return tokens.highBackground
        case "medium": return tokens.mediumBackground
        case "low": return tokens.lowBackground
        default: return tokens.unknownBackground
        }
    }
    implicitWidth: severityText.implicitWidth + tokens.spaceM * 2
    implicitHeight: Math.max(32, severityText.implicitHeight + tokens.spaceS)
    radius: tokens.radiusS
    color: fillColor
    Accessible.role: Accessible.StaticText
    Accessible.name: qsTr("Severity: %1").arg(displayLabel)
    Controls.Label {
        id: severityText
        anchors.centerIn: parent
        text: badge.displayLabel
        color: tokens.severityForeground
        font.pixelSize: tokens.captionSize
        font.weight: Font.DemiBold
    }
}

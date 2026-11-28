// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

ColumnLayout {
    id: chart
    required property string heading
    required property list<string> labels
    required property list<int> values
    readonly property bool available: labels.length > 0 && values.length === labels.length
    // Serialize the sequence without a JavaScript numeric indexing loop.
    // Qt's AOT generator otherwise introduces double/qsizetype conversions.
    readonly property string countsText: chart.available ? chart.values.join(",") : ""
    spacing: 6
    Controls.Label {
        Layout.fillWidth: true
        text: chart.heading
        font.bold: true
        wrapMode: Text.WordWrap
        Accessible.role: Accessible.Heading
    }
    Controls.Label {
        Layout.fillWidth: true
        visible: !chart.available
        text: qsTr("Unavailable — no authorized current snapshot.")
        wrapMode: Text.WordWrap
    }
    Repeater {
        model: chart.available ? chart.labels.length : 0
        delegate: RowLayout {
            id: barRow
            required property int index
            readonly property int count: index < chart.values.length ? chart.values[index] : 0
            Layout.fillWidth: true
            Controls.Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 150
                text: barRow.index < chart.labels.length ? chart.labels[barRow.index] : ""
                wrapMode: Text.WordWrap
            }
            Rectangle {
                id: track
                Layout.fillWidth: true
                Layout.preferredWidth: 180
                Layout.minimumWidth: 20
                Layout.preferredHeight: 16
                radius: 3
                color: Kirigami.Theme.backgroundColor
                border.color: Kirigami.Theme.textColor
                Accessible.ignored: true
                Rectangle {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    height: Math.max(0, track.height - 4)
                    width: Math.max(0, track.width - 2) * Math.min(8, Math.max(0, barRow.count)) / 8
                    radius: 2
                    color: Kirigami.Theme.highlightColor
                }
            }
            Controls.Label {
                text: String(barRow.count)
                Accessible.name: qsTr("%1: %2 records").arg(barRow.index < chart.labels.length ? chart.labels[barRow.index] : "").arg(barRow.count)
            }
        }
    }
}

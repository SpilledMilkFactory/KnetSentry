// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

// M1.4: a navigable presentation-only shell, with NO live SIEM data sources.
Kirigami.ApplicationWindow {
    id: window
    objectName: "knetSentryMainWindow"
    title: qsTr("KnetSentry — %1").arg(activeSectionTitle)
    width: 1100
    height: 720
    minimumWidth: 700
    minimumHeight: 480
    visible: true

    // Public, non-privileged navigation state. Used by the headless C++
    // integration test to exercise exactly the same routing as drawer actions.
    property string activeSection: "dashboard"
    property string navigationRequest: ""
    readonly property string currentPageSection: pageStack.currentItem
                                                 ? pageStack.currentItem.sectionId : ""
    readonly property int navigationDepth: pageStack.depth
    readonly property string activeSectionTitle: {
        switch (activeSection) {
        case "dashboard": return qsTr("Dashboard")
        case "assets": return qsTr("Assets")
        case "events": return qsTr("Events")
        case "detections": return qsTr("Detections")
        case "alerts": return qsTr("Alerts")
        case "investigations": return qsTr("Investigations")
        case "settings": return qsTr("Settings")
        default: return qsTr("Unknown")
        }
    }

    function isValidSection(sectionId) {
        return ["dashboard", "assets", "events", "detections", "alerts",
                "investigations", "settings"].indexOf(sectionId) !== -1
    }

    function navigateTo(sectionId) {
        if (!isValidSection(sectionId)) {
            return false
        }
        if (activeSection === sectionId) {
            return true
        }
        // These are TOP-LEVEL destinations, not drill-down history. Replacing
        // the current page keeps the navigation stack bounded at depth one.
        const page = pageStack.replace(sectionPageComponent, { "sectionId": sectionId })
        if (!page) {
            return false
        }
        activeSection = sectionId
        return true
    }

    onNavigationRequestChanged: {
        if (navigationRequest.length > 0) {
            navigateTo(navigationRequest)
        }
    }

    globalDrawer: Kirigami.GlobalDrawer {
        title: qsTr("KnetSentry")
        titleIcon: "security-high"
        isMenu: false
        actions: [
            Kirigami.Action {
                text: qsTr("Dashboard")
                icon.name: "view-dashboard"
                shortcut: "Ctrl+1"
                onTriggered: window.navigateTo("dashboard")
            },
            Kirigami.Action {
                text: qsTr("Assets")
                icon.name: "network-wired"
                shortcut: "Ctrl+2"
                onTriggered: window.navigateTo("assets")
            },
            Kirigami.Action {
                text: qsTr("Events")
                icon.name: "view-list-details"
                shortcut: "Ctrl+3"
                onTriggered: window.navigateTo("events")
            },
            Kirigami.Action {
                text: qsTr("Detections")
                icon.name: "security-medium"
                shortcut: "Ctrl+4"
                onTriggered: window.navigateTo("detections")
            },
            Kirigami.Action {
                text: qsTr("Alerts")
                icon.name: "dialog-warning"
                shortcut: "Ctrl+5"
                onTriggered: window.navigateTo("alerts")
            },
            Kirigami.Action {
                text: qsTr("Investigations")
                icon.name: "system-search"
                shortcut: "Ctrl+6"
                onTriggered: window.navigateTo("investigations")
            },
            Kirigami.Action {
                text: qsTr("Settings")
                icon.name: "settings-configure"
                shortcut: "Ctrl+7"
                onTriggered: window.navigateTo("settings")
            }
        ]
    }

    Component {
        id: sectionPageComponent
        SectionPage {}
    }

    pageStack.initialPage: SectionPage { sectionId: "dashboard" }

    footer: Controls.ToolBar {
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Kirigami.Units.largeSpacing
            anchors.rightMargin: Kirigami.Units.largeSpacing
            Controls.Label {
                text: qsTr("Monitoring is not active — navigation preview only")
                Layout.fillWidth: true
                elide: Text.ElideRight
            }
            Controls.Label {
                text: qsTr("M1.4")
            }
        }
    }
}

// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
import QtQml
import QtQuick

// M1.5: presentation-only token catalogue. No telemetry, credentials or IPC.
// Platform-managed text/surface colors come from Kirigami.Theme, not here.
QtObject {
    readonly property string version: "M1.5"
    readonly property int spaceXs: 4
    readonly property int spaceS: 8
    readonly property int spaceM: 12
    readonly property int spaceL: 20
    readonly property int spaceXl: 28
    readonly property int radiusS: 6
    readonly property int radiusM: 10
    property real textScale: 1.0
    readonly property int titleSize: Math.round(27 * textScale)
    readonly property int sectionSize: Math.round(17 * textScale)
    readonly property int bodySize: Math.round(14 * textScale)
    readonly property int captionSize: Math.round(12 * textScale)
    readonly property int touchTarget: 40
    readonly property int compactBreakpoint: 820
    // Motion is deliberately opt-in for future transitions. No animated
    // security urgency or critical flashing is permitted.
    readonly property int durationFast: 120
    readonly property int durationNormal: 180
    readonly property int durationReduced: 0
    readonly property bool animateStatusChanges: false
    // Semantic severity samples only. Never use these to indicate availability,
    // health, confidence, missing data or a successful monitoring state.
    readonly property color criticalBackground: "#991b2b"
    readonly property color highBackground: "#994411"
    readonly property color mediumBackground: "#755400"
    readonly property color lowBackground: "#245c41"
    readonly property color unknownBackground: "#44546b"
    readonly property color severityForeground: "#ffffff"
}

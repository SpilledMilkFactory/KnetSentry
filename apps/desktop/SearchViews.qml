// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
import QtQml

// Session-only categorical definitions, never evidence or authorization.
QtObject {
    property bool eventSaved: false
    property int eventCollector: 0
    property int eventOutcome: 0
    property bool eventDescending: false
    property bool alertSaved: false
    property int alertSeverity: 0

    function saveEvents(collector: int, outcome: int, descending: bool): bool {
        if (collector < 0 || collector > 3 || outcome < 0 || outcome > 3)
            return false
        eventCollector = collector
        eventOutcome = outcome
        eventDescending = descending
        eventSaved = true
        return true
    }

    function saveAlerts(severity: int): bool {
        if (severity < 0 || severity > 6)
            return false
        alertSeverity = severity
        alertSaved = true
        return true
    }

    function forgetEvents(): void {
        eventSaved = false
        eventCollector = 0
        eventOutcome = 0
        eventDescending = false
    }

    function forgetAlerts(): void {
        alertSaved = false
        alertSeverity = 0
    }
}

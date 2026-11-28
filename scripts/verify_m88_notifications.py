#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Notification privacy and record palette registration; runtime separate."""
from pathlib import Path
from verify_m17_suites import NONSAN_DESKTOP_TESTS

ROOT = Path(__file__).resolve().parent.parent


def require(condition, message):
    if not condition:
        raise ValueError('M8.8: ' + message)


def main():
    header = (ROOT / 'apps/desktop/alert_model.hpp').read_text()
    model = (ROOT / 'apps/desktop/alert_model.cpp').read_text()
    page = (ROOT / 'apps/desktop/SectionPage.qml').read_text()
    main_cpp = (ROOT / 'apps/desktop/main.cpp').read_text()
    window = (ROOT / 'apps/desktop/Main.qml').read_text()
    for marker in ('notifications_enabled_{}, attention_enabled_{}', 'notificationCount READ',
                   'notificationHistoryText READ', 'activePageCount READ'):
        require(marker in header, marker)
    require('busy_ || !expiry_.isActive()' in model, 'current snapshot bound')
    require('row.status == 0 || row.status == 1' in model, 'active lifecycle definition')
    require('request_.operation == service::AlertQuery::Operation::List' in model, 'list only')
    require('if (!enabled) { notification_history_.clear(); }' in model, 'disable clears')
    require('notification_history_.size() >= 8' in model and 'notification_history_.removeLast()' in model, 'bounded history')
    require(model.count('notification_history_.prepend(') == 1 and
            'notification_history_.prepend(tr("Stored alert page request ended. Consult Alerts for current status."))' in model,
            'fixed generic content only')
    require('alerts.attentionEnabled() && !window->isActive()' in main_cpp and
            'window->alert(3000)' in main_cpp, 'opt-in bounded window attention')
    for marker in ('palette.highlightedText : palette.windowText', 'palette.highlight : palette.window'):
        require(page.count(marker) == 3, 'all three record color pairs: ' + marker)
    for row in ('eventRow', 'alertRow', 'timelineRow'):
        require(f'color: {row}.recordForeground' in page and f'color: {row}.recordBackground' in page, 'paired rendering: ' + row)
    require('ratio >= 4.5' in page and 'contrast >= 4.5' in main_cpp, 'record contrast fallback and runtime assertion')
    require('notificationCount > 0' in window and 'clearNotificationHistory()' in page, 'history controls')
    require('record_palette_matches(list, true)' in main_cpp and 'record_palette_matches(list, false)' in main_cpp, 'rendered pairs')
    require('self-test-notifications' in main_cpp and
            'M8.8 notification privacy, bounded history and current-page indicator: PASS' in main_cpp, 'rendered notice contract')
    require('before[0] + 11' in (ROOT / 'tests/alert_interface_runtime_m77.py').read_text(), 'exact explicit read count')
    require({'knetsentry_gui_alert_interface_runtime', 'knetsentry_gui_event_explorer_runtime',
             'knetsentry_gui_investigation_runtime'} <= NONSAN_DESKTOP_TESTS, 'mandatory desktop tests')
    require('NOTIFICATIONS_M88.md' in (ROOT / 'docs/README.md').read_text(), 'documentation index')
    print('M8.8 notification privacy and record palette registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

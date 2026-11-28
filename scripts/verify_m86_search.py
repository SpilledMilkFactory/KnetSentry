#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M8.6 source registration; actual Qt and manager tests qualify behavior."""
from pathlib import Path
from verify_m17_suites import NONSAN_DESKTOP_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'apps/desktop/CMakeLists.txt': ('SearchViews.qml',),
        'apps/desktop/Main.qml': ('SearchViews { id: savedSearchViews }', 'onSearchDestinationRequested:', 'window.navigateTo(destination)'),
        'apps/desktop/SearchViews.qml': ('collector < 0 || collector > 3', 'outcome < 0 || outcome > 3', 'severity < 0 || severity > 6', 'forgetEvents()', 'forgetAlerts()'),
        'apps/desktop/SectionPage.qml': ('required property SearchViews searchViews', 'page.eventModel.clear()', 'eventSource.text = ""', 'page.alertModel.clear()', 'page.searchViews.saveEvents(', 'page.searchViews.saveAlerts(', 'page.searchDestinationRequested("investigations")', 'page.eventModel.search(', 'page.alertModel.search('),
        'apps/desktop/event_explorer_model.cpp': ('valid_event_query(query_)', 'More matching records available.', 'End of matching results.'),
        'apps/desktop/alert_model.cpp': ('filter < -1 || filter > 5', 'More matching records available.', 'End of matching results.'),
        'apps/desktop/main.cpp': ('M8.6 rendered event presets, saved views and cross-view clearing: PASS', 'M8.6 rendered alert presets, saved views and cross-view clearing: PASS'),
        'tests/event_explorer_runtime_m68.py': ('query_count() - before == 4', 'M8.6 rendered event presets'),
        'tests/alert_interface_runtime_m77.py': ('query_count() - before == 5', 'M8.6 rendered alert presets'),
        'docs/README.md': ('SEARCH_FILTERING_M86.md',),
    }
    for name, markers in checks.items():
        if not all(marker in (ROOT / name).read_text(encoding='utf-8') for marker in markers):
            raise ValueError('M8.6 missing registration: ' + name)
    views = (ROOT / 'apps/desktop/SearchViews.qml').read_text(encoding='utf-8')
    if any(marker in views for marker in ('property string', 'property var', 'Settings {', 'LocalStorage', 'XMLHttpRequest', 'Model.')):
        raise ValueError('M8.6 unexpected saved-view authority or data')
    if not {'knetsentry_gui_event_explorer_runtime', 'knetsentry_gui_alert_interface_runtime'} <= NONSAN_DESKTOP_TESTS:
        raise ValueError('M8.6 mandatory test scope changed')
    print('M8.6 search and saved-view registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

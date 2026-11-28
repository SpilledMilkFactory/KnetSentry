#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M8.1 registration checks; runtime and UI verification remain separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS, NONSAN_DESKTOP_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'apps/desktop/CMakeLists.txt': ('dashboard_model.cpp', 'dashboard_model.hpp'),
        'apps/desktop/Main.qml': ('dashboardModel.clear()', 'dashboardRefreshButton'),
        'apps/desktop/SectionPage.qml': ('dashboardModel.eventSummary', 'dashboardModel.alertSummary',
                                         'dashboardModel.detectionSummary', 'healthModel.dashboardRegistry'),
        'apps/desktop/dashboard_model.cpp': ('begin_events', 'begin_alerts', 'AlertQuery{}', '30000', 'client_.cancel()'),
        'tests/CMakeLists.txt': ('NAME knetsentry_dashboard_summary_contract', 'NAME knetsentry_gui_dashboard_runtime'),
        'scripts/verify_m12_hardening.py': ('dashboard_summary_m81.cpp', 'knetsentry_dashboard_summary_test', 'dashboard_model.cpp'),
        'docs/README.md': ('SOC_DASHBOARD_M81.md',),
    }
    for path, markers in checks.items():
        source = (ROOT / path).read_text()
        if not all(marker in source for marker in markers):
            raise ValueError('M8.1 missing registration: ' + path)
    if 'knetsentry_dashboard_summary_contract' not in CORE_TESTS or 'knetsentry_gui_dashboard_runtime' not in NONSAN_DESKTOP_TESTS:
        raise ValueError('M8.1 missing mandatory suite registration')
    print('M8.1 dashboard registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

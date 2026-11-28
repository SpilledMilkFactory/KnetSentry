#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M8.2 source registration; runtime and workload qualification remain separate."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'apps/desktop/CMakeLists.txt': ('SnapshotBars.qml',),
        'apps/desktop/SectionPage.qml': ('dashboardModel.eventHistogram', 'dashboardModel.activityCounts',
                                         'dashboardModel.severityCounts', 'dashboardModel.activityFilter',
                                         'dashboardModel.severityFilter'),
        'apps/desktop/dashboard_model.cpp': ('event_chart_.reset()', 'alert_chart_.reset()', 'setActivityFilter',
                                             'setSeverityFilter'),
        'apps/desktop/main.cpp': ('M8.2 rendered chart values, local filters and clearing: PASS',),
        'tests/dashboard_summary_m81.cpp': ('receiver age boundaries and extreme timestamps',
                                            'all severity values and resolved exclusion'),
        'tests/dashboard_runtime_m81.py': ('M8.2 rendered chart values, local filters and clearing: PASS',),
        'docs/README.md': ('SECURITY_VISUALIZATIONS_M82.md',),
    }
    for path, markers in checks.items():
        source = (ROOT / path).read_text(encoding='utf-8')
        if not all(marker in source for marker in markers):
            raise ValueError('M8.2 missing registration: ' + path)
    print('M8.2 visualization registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

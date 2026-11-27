#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M7.6 structural registration; compiled runtime qualification is separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'include/knetsentry/detection/alerts.hpp': ('initialize_alerts', 'consume_alerts', 'update_alert', 'read_alerts'),
        'src/agent/alerts.cpp': ('pending_schedule(', 'store.raw(', 'store.normalized(', '::flock(', '::fsync(', '::renameat('),
        'src/agent/CMakeLists.txt': ('alerts.cpp',),
        'tests/CMakeLists.txt': ('NAME knetsentry_alerts_contract', 'knetsentry_apply_project_options(knetsentry_alerts_test)'),
        'scripts/verify_m12_hardening.py': ('alerts.cpp', 'alerts_m76.cpp', 'knetsentry_alerts_test'),
        'docs/README.md': ('ALERT_LIFECYCLE_M76.md',),
        '.gitignore': ('alerts-m76.v1', 'alerts-m76.pending'),
    }
    for name, markers in checks.items():
        source = (ROOT / name).read_text(encoding='utf-8')
        for marker in markers:
            if marker not in source:
                raise ValueError(f'M7.6 missing {marker}: {name}')
    if 'knetsentry_alerts_contract' not in CORE_TESTS:
        raise ValueError('M7.6 mandatory test missing')
    print('M7.6 alert lifecycle registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

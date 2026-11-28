#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M7.8 registration and inventory contract; runtime qualification separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent
NAME = 'knetsentry_detection_recovery_contract'


def main():
    checks = {
        'tests/CMakeLists.txt': (f'NAME {NAME}', 'detection_recovery_m78.cpp',
                                 'knetsentry_apply_project_options(knetsentry_detection_recovery_test)'),
        'scripts/verify_m12_hardening.py': ('detection_recovery_m78.cpp', 'knetsentry_detection_recovery_test'),
        'docs/README.md': ('DETECTION_RECOVERY_M78.md',),
    }
    for path, markers in checks.items():
        source = (ROOT / path).read_text()
        if not all(marker in source for marker in markers):
            raise ValueError('M7.8 missing registration: ' + path)
    if NAME not in CORE_TESTS:
        raise ValueError('M7.8 missing mandatory core test')
    print('M7.8 detection recovery registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

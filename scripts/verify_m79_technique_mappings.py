#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M7.9 registration and inventory contract; runtime qualification separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent
NAME = 'knetsentry_technique_mappings_contract'


def main():
    checks = {
        'src/agent/CMakeLists.txt': ('technique_mappings.cpp',),
        'tests/CMakeLists.txt': (f'NAME {NAME}', 'technique_mappings_m79.cpp',
                                 'knetsentry_apply_project_options(knetsentry_technique_mappings_test)'),
        'scripts/verify_m12_hardening.py': ('technique_mappings_m79.cpp', 'knetsentry_technique_mappings_test'),
        'docs/README.md': ('TECHNIQUE_MAPPINGS_M79.md',),
    }
    for path, markers in checks.items():
        source = (ROOT / path).read_text()
        if not all(marker in source for marker in markers):
            raise ValueError('M7.9 missing registration: ' + path)
    if NAME not in CORE_TESTS:
        raise ValueError('M7.9 missing mandatory core test')
    print('M7.9 technique mappings registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

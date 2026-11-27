#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Structural registration only; compiled system detection is separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'include/knetsentry/detection/system_integrity.hpp': ('detect_system_integrity', 'SystemFinding', 'SystemRule'),
        'include/knetsentry/storage/event_store.hpp': ('audit_type{}',),
        'src/agent/event_store.cpp': ('event.source.audit_type',),
        'src/agent/CMakeLists.txt': ('system_integrity.cpp',),
        'src/agent/system_integrity.cpp': ('store.search(query)', 'store.pending(', 'query.binding = binding'),
        'tests/CMakeLists.txt': ('NAME knetsentry_system_integrity_contract', 'knetsentry_apply_project_options(knetsentry_system_integrity_test)'),
        'scripts/verify_m12_hardening.py': ('system_integrity.cpp', 'system_integrity_m74.cpp', 'knetsentry_system_integrity_test'),
        'docs/README.md': ('SYSTEM_INTEGRITY_M74.md',),
    }
    for name, markers in checks.items():
        source = (ROOT / name).read_text(encoding='utf-8')
        for marker in markers:
            if marker not in source:
                raise ValueError(f'M7.4 missing {marker}: {name}')
    if 'knetsentry_system_integrity_contract' not in CORE_TESTS:
        raise ValueError('M7.4 mandatory test missing')
    print('M7.4 system integrity registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

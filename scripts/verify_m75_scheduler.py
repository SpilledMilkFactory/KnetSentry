#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Structural registration only; compiled scheduler qualification is separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'include/knetsentry/detection/scheduler.hpp': ('initialize_schedule', 'run_schedule', 'acknowledge_schedule'),
        'src/agent/scheduler.cpp': ('store.search(query)', 'store.pending(', '::flock(', '::fsync(', '::renameat(', 'EVP_Digest('),
        'src/agent/CMakeLists.txt': ('scheduler.cpp',),
        'tests/CMakeLists.txt': ('NAME knetsentry_scheduler_contract', 'knetsentry_apply_project_options(knetsentry_scheduler_test)'),
        'scripts/verify_m12_hardening.py': ('scheduler.cpp', 'scheduler_m75.cpp', 'knetsentry_scheduler_test'),
        'docs/README.md': ('RULE_SCHEDULING_M75.md',),
        '.gitignore': ('schedule-m75.v1', 'schedule-m75.pending'),
    }
    for name, markers in checks.items():
        source = (ROOT / name).read_text(encoding='utf-8')
        for marker in markers:
            if marker not in source:
                raise ValueError(f'M7.5 missing {marker}: {name}')
    if 'knetsentry_scheduler_contract' not in CORE_TESTS:
        raise ValueError('M7.5 mandatory test missing')
    print('M7.5 scheduler registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

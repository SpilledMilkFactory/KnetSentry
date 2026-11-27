#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Structural registration only; compiled pattern detection is separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'include/knetsentry/detection/authentication_patterns.hpp': ('detect_authentication', 'AuthenticationPolicy', 'AuthenticationFinding'),
        'src/agent/CMakeLists.txt': ('authentication_patterns.cpp',),
        'src/agent/authentication_patterns.cpp': ('ValidatedRuleSet::compile', 'store.search(query)', 'store.pending(', 'query.binding = binding'),
        'tests/CMakeLists.txt': ('NAME knetsentry_authentication_patterns_contract', 'knetsentry_apply_project_options(knetsentry_authentication_patterns_test)'),
        'scripts/verify_m12_hardening.py': ('authentication_patterns.cpp', 'authentication_patterns_m73.cpp', 'knetsentry_authentication_patterns_test'),
        'docs/README.md': ('AUTHENTICATION_PATTERNS_M73.md',),
    }
    for name, markers in checks.items():
        source = (ROOT / name).read_text(encoding='utf-8')
        for marker in markers:
            if marker not in source:
                raise ValueError(f'M7.3 missing {marker}: {name}')
    if 'knetsentry_authentication_patterns_contract' not in CORE_TESTS:
        raise ValueError('M7.3 mandatory test missing')
    print('M7.3 authentication pattern registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

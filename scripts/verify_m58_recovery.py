#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline M5.8 registration checks; failure recovery requires executed CTest."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_collector_recovery_contract'
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    if name not in CORE_TESTS or f'NAME {name}' not in tests:
        raise ValueError('missing mandatory recovery regression')
    for marker in ('collector_recovery_m58.cpp', 'knetsentry_apply_project_options(knetsentry_collector_recovery_test)',
                   f'set_tests_properties({name} PROPERTIES LABELS "integration;security;regression;privacy" TIMEOUT 75)'):
        if marker not in tests:
            raise ValueError('missing recovery build requirement: ' + marker)
    if 'knetsentry_collector_recovery_test' not in (ROOT / 'scripts/verify_m12_hardening.py').read_text():
        raise ValueError('missing recovery binary hardening verification')
    if 'COLLECTOR_RECOVERY_M58.md' not in (ROOT / 'docs/README.md').read_text():
        raise ValueError('missing recovery documentation index')
    if 'M5.8 TLS receiver and sender commit failures' not in (ROOT / 'tests/enrollment_m44.cpp').read_text():
        raise ValueError('missing composed delivery recovery regression')
    print('M5.8 collector and delivery recovery registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline M4.8 registration contract; actual TLS evidence requires CTest."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    name = 'knetsentry_authentication_transport_regression'
    cmake = (ROOT / 'tests/CMakeLists.txt').read_text()
    source = (ROOT / 'tests/enrollment_m44.cpp').read_text()
    require(name in CORE_TESTS and f'NAME {name}' in cmake and
            '--authentication-transport' in cmake and
            'authentication_transport(fixture)' in source, 'missing mandatory M4.8 runtime registration')
    require(f'set_tests_properties({name} PROPERTIES LABELS "integration;security;regression;privacy" TIMEOUT 30)' in cmake,
            'missing M4.8 labels or timeout')
    require('AUTHENTICATION_TRANSPORT_REGRESSIONS_M48.md' in (ROOT / 'docs/README.md').read_text(),
            'missing M4.8 documentation index')
    print('M4.8 authentication and transport regression registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

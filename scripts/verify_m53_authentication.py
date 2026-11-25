#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline registration and opt-in authentication boundary checks."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_authentication_collection_contract'
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    native = (ROOT / 'src/agent/systemd_journal.cpp').read_text()
    store = (ROOT / 'src/agent/journal.cpp').read_text()
    docs = (ROOT / 'docs/README.md').read_text()
    if name not in CORE_TESTS or f'NAME {name}' not in tests:
        raise ValueError('missing mandatory M5.3 regression')
    if 'if (mode_ == JournalMode::Authentication)' not in native or 'classify_auth(' not in native:
        raise ValueError('missing opt-in classification')
    if 'auth-m53.v1' not in store or 'KNETSENTRY-AUTH-V1' not in store or 'valid_auth_event' not in store:
        raise ValueError('missing distinct state contract')
    if 'AUTHENTICATION_COLLECTION_M53.md' not in docs:
        raise ValueError('missing documentation index')
    print('M5.3 authentication collection registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

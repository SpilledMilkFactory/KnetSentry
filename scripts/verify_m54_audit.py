#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline registration checks for the opt-in journal-mediated audit collector."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_audit_collection_contract'
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    native = (ROOT / 'src/agent/systemd_journal.cpp').read_text()
    store = (ROOT / 'src/agent/journal.cpp').read_text()
    docs = (ROOT / 'docs/README.md').read_text()
    if name not in CORE_TESTS or f'NAME {name}' not in tests:
        raise ValueError('missing mandatory M5.4 regression')
    for marker in ('_TRANSPORT=audit', '_AUDIT_TYPE', '_AUDIT_ID', 'JournalMode::Audit'):
        if marker not in native:
            raise ValueError('missing audit source contract')
    for marker in ('audit-m54.v1', 'audit-m54.pending', 'KNETSENTRY-AUDIT-V1'):
        if marker not in store:
            raise ValueError('missing audit state contract')
    if 'AUDIT_COLLECTION_M54.md' not in docs:
        raise ValueError('missing documentation index')
    print('M5.4 audit collection registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

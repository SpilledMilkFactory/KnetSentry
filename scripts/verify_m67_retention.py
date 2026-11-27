#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline storage policy registration; actual quota behavior requires runtime tests."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_storage_retention_contract'
    for path, tokens in (
        ('include/knetsentry/storage/event_store.hpp', ('StoragePolicy', 'StorageUsage', 'preview_cleanup', 'apply_cleanup')),
        ('src/agent/event_store.cpp', ('valid_storage_policy', 'quota_warning', 'policy().record_limit', 'policy().wire_byte_limit', 'apply_retention(plan)')),
        ('src/agent/sqlite_event_store.cpp', ('PRAGMA max_page_count=', 'PRAGMA freelist_count', 'verify_store(db)', 'policy().record_limit', 'policy().wire_byte_limit')),
        ('tests/CMakeLists.txt', (f'NAME {name}',)),
        ('scripts/verify_m12_hardening.py', ('storage_retention_m67.cpp', 'knetsentry_storage_retention_test')),
        ('docs/README.md', ('STORAGE_RETENTION_M67.md',)),
    ):
        source = (ROOT / path).read_text()
        for token in tokens:
            if token not in source:
                raise ValueError('missing retention contract: ' + token)
    if name not in CORE_TESTS:
        raise ValueError('missing mandatory regression')
    print('M6.7 retention, quota and warning registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M6.9 offline registration. Runtime failure recovery must be tested separately."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'tests/storage_recovery_m69.cpp': ('sqlite3_db_cacheflush', 'SIGKILL', 'RLIMIT_FSIZE', 'BEGIN IMMEDIATE', 'PRAGMA user_version=3', 'database_page_limit = 16', 'timestamp_contract'),
        'tests/enrollment_m44.cpp': ('class RecoverySink', '--ingestion-recovery', 'StoreStatus::Capacity', 'IngestOutcome', 'normalized_event()', 'SqliteEventStore'),
        'tests/CMakeLists.txt': ('knetsentry_apply_project_options(knetsentry_storage_recovery_test)', 'KnetSentry::SqliteStorage', '--ingestion-recovery'),
        'scripts/verify_m12_hardening.py': ('storage_recovery_m69.cpp', 'knetsentry_storage_recovery_test'),
        'docs/README.md': ('STORAGE_RECOVERY_M69.md',),
    }
    for path, markers in checks.items():
        source = (ROOT / path).read_text(encoding='utf-8')
        for marker in markers:
            if marker not in source:
                raise ValueError(f'M6.9 missing {marker}: {path}')
    tests = (ROOT / 'tests/CMakeLists.txt').read_text(encoding='utf-8')
    for name in ('knetsentry_storage_recovery_contract', 'knetsentry_ingestion_recovery_contract'):
        if name not in CORE_TESTS or f'NAME {name}' not in tests:
            raise ValueError(f'M6.9 mandatory test missing: {name}')
    print('M6.9 ingestion and storage recovery registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

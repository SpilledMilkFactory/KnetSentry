#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Source registration and checked SQLite/enum boundary (runtime separate)."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    def read(path):
        return (ROOT / path).read_text()
    name = 'knetsentry_sqlite_storage_contract'
    if name not in CORE_TESTS or f'NAME {name}' not in read('tests/CMakeLists.txt'):
        raise ValueError('missing mandatory SQLite test')
    source = read('src/agent/sqlite_event_store.cpp')
    for token in ('SQLITE_OPEN_NOFOLLOW', 'SQLITE_DBCONFIG_DEFENSIVE', 'SQLITE_DBCONFIG_TRUSTED_SCHEMA',
                  'SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION', 'BEGIN IMMEDIATE', 'COMMIT', 'ROLLBACK',
                  'PRAGMA user_version=2', 'PRAGMA synchronous=EXTRA', 'PRAGMA integrity_check(1)',
                  'sqlite3_bind_text', 'decode_journal_mode', 'normalize_event', 'RESOLVE_NO_SYMLINKS'):
        if token not in source:
            raise ValueError('missing SQLite contract: ' + token)
    if 'static_cast<J>(99)' in read('tests/normalization_m62.cpp') or 'decode_journal_mode(99)' not in read('tests/normalization_m62.cpp'):
        raise ValueError('invalid mode must be checked before enum interpretation')
    if '--warnings-as-errors=clang-analyzer-*' not in read('cmake/KnetSentryBuildOptions.cmake'):
        raise ValueError('analyzer diagnostic must be fatal')
    for path in ('src/agent/ingestion.cpp', 'src/agent/delivery.cpp'):
        if 'SqliteEventStore' in read(path):
            raise ValueError('development backend must not authorize ACK')
    if 'SQLite::SQLite3' not in read('src/agent/CMakeLists.txt') or 'libsqlite3-dev' not in read('scripts/ci/install_dependencies.sh'):
        raise ValueError('missing distro SQLite dependency registration')
    if 'SQLITE_STORAGE_M64.md' not in read('docs/README.md') or 'sqlite_storage_m64.cpp' not in read('scripts/verify_m12_hardening.py'):
        raise ValueError('missing documentation/hardening registration')
    print('M6.4 SQLite schema, transaction, enum validation and registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

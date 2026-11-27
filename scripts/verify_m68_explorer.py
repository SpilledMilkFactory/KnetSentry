#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline M6.8 registration; actual query and UI runtime qualification is separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS, NONSAN_DESKTOP_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = (
        ('src/service/local_ipc.cpp', ('IpcAction::Events', 'audit.persistent()', 'AuditEvent::EventsAuthorized', 'query_events', 'SO_PEERCRED')),
        ('apps/manager/main.cpp', ('--event-store-dir', 'StorageOpenMode::ExistingV4', 'audit_dir.empty()', 'set_event_store')),
        ('src/service/health_client.cpp', ('decode_event_page', 'verify_peer()', 'max_event_response')),
        ('apps/desktop/event_explorer_model.hpp', ('QAbstractListModel', 'QML_UNCREATABLE')),
        ('apps/desktop/SectionPage.qml', ('ListView', 'reuseItems: true', 'eventModel.next()', 'Text.PlainText')),
        ('src/agent/sqlite_event_store.cpp', ('ORDER BY id DESC', 'verify_store(db)', 'StorageOpenMode::ExistingV4')),
        ('include/knetsentry/service/event_query.hpp', ('event_page_size = 8', 'max_event_request = 256', 'max_event_response = 4096')),
        ('docs/README.md', ('EVENT_EXPLORER_M68.md',)),
        ('scripts/verify_m12_hardening.py', ('event_explorer_m68.cpp', 'event_explorer_model.cpp', 'knetsentry_event_explorer_test')),
    )
    for path, markers in checks:
        text = (ROOT / path).read_text()
        for marker in markers:
            if marker not in text:
                raise ValueError(f'M6.8 missing {marker}: {path}')
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    for name in ('knetsentry_event_explorer_contract', 'knetsentry_event_explorer_runtime', 'knetsentry_gui_event_explorer_runtime'):
        if name not in CORE_TESTS | NONSAN_DESKTOP_TESTS or f'NAME {name}' not in tests:
            raise ValueError('missing test: ' + name)
    if 'KnetSentry::SqliteStorage' in (ROOT / 'apps/desktop/CMakeLists.txt').read_text():
        raise ValueError('desktop SQLite linkage forbidden')
    print('M6.8 event explorer, bounded IPC and GUI registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

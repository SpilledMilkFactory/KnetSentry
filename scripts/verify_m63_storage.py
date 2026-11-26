#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Check registration and the non-durable reference storage boundary."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_event_storage_contract'
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    header = (ROOT / 'include/knetsentry/storage/event_store.hpp').read_text()
    source = (ROOT / 'src/agent/event_store.cpp').read_text()
    hardening = (ROOT / 'scripts/verify_m12_hardening.py').read_text()
    if name not in CORE_TESTS or f'NAME {name}' not in tests:
        raise ValueError('missing mandatory storage regression')
    for token in ('class EventStore', 'class MemoryEventStore final : public EventStore', 'Durability::Volatile',
                  'preview_retention', 'apply_retention', 'PendingPage'):
        if token not in header:
            raise ValueError('missing storage interface: ' + token)
    if 'Durability::Durable' in source or 'parse_delivery_row' not in source or 'normalize_event' not in source:
        raise ValueError('reference backend must remain volatile with canonical validation')
    if 'MemoryEventStore' in (ROOT / 'src/agent/ingestion.cpp').read_text():
        raise ValueError('volatile reference store must not enter durable ingestion')
    if 'event_store.cpp' not in (ROOT / 'src/agent/CMakeLists.txt').read_text() or 'event_storage_m63.cpp' not in hardening or 'knetsentry_event_storage_test' not in hardening:
        raise ValueError('missing storage build or hardening registration')
    if 'EVENT_STORAGE_M63.md' not in (ROOT / 'docs/README.md').read_text():
        raise ValueError('missing storage documentation index')
    print('M6.3 database-independent volatile storage contract: PASS (runtime separate)')


if __name__ == '__main__':
    main()

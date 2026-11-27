#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline search registration; correctness and index behavior require runtime tests."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_event_search_contract'
    source = (ROOT / 'src/agent/sqlite_event_store.cpp').read_text()
    for token in ('PRAGMA user_version=4', 'event_mode', 'event_source', 'event_time',
                  'valid_search_query(q)', 'matches_search_query(q, v.raw, v.event)',
                  'verify_store(db)', 'unit=?8', 'mode=?9', 'class_uid=?10',
                  'activity_id=?11', 'mapping=?12', 'q.limit + 1'):
        if token not in source:
            raise ValueError('missing search contract: ' + token)
    reference = (ROOT / 'src/agent/event_store.cpp').read_text()
    if 'valid_search_query(query)' not in reference or 'matches_search_query(query, entry.raw, event)' not in reference:
        raise ValueError('missing shared reference query validation')
    if name not in CORE_TESTS or f'NAME {name}' not in (ROOT / 'tests/CMakeLists.txt').read_text():
        raise ValueError('missing mandatory event search regression')
    if 'event_search_m66.cpp' not in (ROOT / 'scripts/verify_m12_hardening.py').read_text():
        raise ValueError('missing hardening registration')
    if 'EVENT_SEARCH_M66.md' not in (ROOT / 'docs/README.md').read_text():
        raise ValueError('missing documentation registration')
    print('M6.6 event search, filter and index registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

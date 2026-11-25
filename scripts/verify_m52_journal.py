#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M5.2 registration and source-boundary contract; runtime qualification is separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_journal_collection_contract'
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    cmake = (ROOT / 'src/agent/CMakeLists.txt').read_text()
    source = (ROOT / 'src/agent/systemd_journal.cpp').read_text()
    docs = (ROOT / 'docs/README.md').read_text()
    if name not in CORE_TESTS or f'NAME {name}' not in tests:
        raise ValueError('missing mandatory M5.2 test')
    for marker in ('PkgConfig::SYSTEMD', 'knetsentry_apply_project_options(knetsentry_agent_journal)'):
        if marker not in cmake:
            raise ValueError('missing native dependency or hardening contract')
    for marker in ('SD_JOURNAL_LOCAL_ONLY', 'sd_journal_test_cursor', 'sd_journal_get_monotonic_usec',
                   'sd_journal_get_realtime_usec', '_SYSTEMD_UNIT', '_MACHINE_ID'):
        if marker not in source:
            raise ValueError('missing native selection/provenance/cursor contract')
    if '"MESSAGE"' in source or 'JOURNAL_COLLECTION_M52.md' not in docs:
        raise ValueError('privacy boundary or documentation index missing')
    print('M5.2 native journal and cursor registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Check M6.1 registration and source boundaries; runtime tests remain required."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_event_ingestion_contract'
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    header = (ROOT / 'include/knetsentry/agent/delivery.hpp').read_text()
    receiver = (ROOT / 'src/agent/delivery.cpp').read_text().split('DeliveryState DeliveryReceiver::step', 1)[1]
    ingestion = (ROOT / 'src/agent/ingestion.cpp').read_text()
    if name not in CORE_TESTS or f'NAME {name}' not in tests or '--ingestion' not in tests:
        raise ValueError('missing mandatory ingestion regression')
    if 'max_inflight = 4' not in header or 'max_row = 2048' not in header:
        raise ValueError('missing bounded admission contract')
    if not receiver.index('enrollment::revalidate') < receiver.index('pipeline_.reserve()') < receiver.index('receive(session_') < receiver.index('pipeline_.process(payload, normalized_)') < receiver.index('session_.write(bytes(ack_))'):
        raise ValueError('ingestion boundary order changed')
    if not ingestion.index('payload.starts_with(binding_)') < ingestion.index('normalize_event') < ingestion.index('sink_.commit'):
        raise ValueError('validation must precede durable commitment')
    if 'ingestion.cpp' not in (ROOT / 'src/agent/CMakeLists.txt').read_text() or 'ingestion.cpp' not in (ROOT / 'scripts/verify_m12_hardening.py').read_text():
        raise ValueError('missing ingestion compilation or hardening registration')
    if 'EVENT_INGESTION_M61.md' not in (ROOT / 'docs/README.md').read_text():
        raise ValueError('missing ingestion documentation index')
    print('M6.1 bounded authenticated ingestion and receipt ordering: PASS (runtime separate)')


if __name__ == '__main__':
    main()

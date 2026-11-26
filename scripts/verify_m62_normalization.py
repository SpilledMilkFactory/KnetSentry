#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Check pinned normalization registration and durable result ordering."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_event_normalization_contract'
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    header = (ROOT / 'include/knetsentry/agent/normalization.hpp').read_text()
    normalizer = (ROOT / 'src/agent/normalization.cpp').read_text()
    ingestion = (ROOT / 'src/agent/ingestion.cpp').read_text()
    if name not in CORE_TESTS or f'NAME {name}' not in tests:
        raise ValueError('missing mandatory normalization regression')
    if 'schema_version = "1.4.0"' not in header or 'mapping_revision = 1' not in header:
        raise ValueError('schema or mapping pin changed without review')
    if 'parse_delivery_row' not in normalizer or 'valid_delivery_binding' not in normalizer:
        raise ValueError('shared canonical validation missing')
    if not ingestion.index('normalize_event') < ingestion.index('sink_.commit') < ingestion.index('normalized = std::move(event)'):
        raise ValueError('normalization must precede commitment; exposure must follow commitment')
    hardening = (ROOT / 'scripts/verify_m12_hardening.py').read_text()
    if 'normalization.cpp' not in (ROOT / 'src/agent/CMakeLists.txt').read_text() or 'normalization_m62.cpp' not in hardening or 'knetsentry_normalization_test' not in hardening:
        raise ValueError('missing normalization build or hardening registration')
    if 'EVENT_NORMALIZATION_M62.md' not in (ROOT / 'docs/README.md').read_text():
        raise ValueError('missing normalization documentation index')
    print('M6.2 pinned normalization and durable result ordering: PASS (runtime separate)')


if __name__ == '__main__':
    main()

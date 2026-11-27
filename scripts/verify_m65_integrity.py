#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Structural integrity registration; cryptographic behavior is tested at runtime."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_evidence_integrity_contract'
    source = (ROOT / 'src/agent/sqlite_event_store.cpp').read_text()
    for token in ('EVP_Q_digest', 'CRYPTO_memcmp', 'PRAGMA user_version=3',
                  'LegacyIntegrityPolicy::EstablishBaseline', 'IntegrityOrigin::LegacyBaseline',
                  'IntegrityOrigin::Admission', 'ON DELETE CASCADE', 'verify_store(db)',
                  'INSERT INTO evidence_integrity'):
        if token not in source:
            raise ValueError('missing integrity contract: ' + token)
    if name not in CORE_TESTS or f'NAME {name}' not in (ROOT / 'tests/CMakeLists.txt').read_text():
        raise ValueError('missing mandatory integrity regression')
    if 'evidence_integrity_m65.cpp' not in (ROOT / 'scripts/verify_m12_hardening.py').read_text():
        raise ValueError('missing hardening registration')
    if 'EVIDENCE_INTEGRITY_M65.md' not in (ROOT / 'docs/README.md').read_text():
        raise ValueError('missing documentation registration')
    print('M6.5 evidence integrity and migration registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M4.5 offline source contract; compiled lifecycle regressions are separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def require(condition, label):
    if not condition:
        raise ValueError(label)


def main():
    registry = (ROOT / 'src/core/enrollment.cpp').read_text()
    tls = (ROOT / 'src/core/tls_transport.cpp').read_text()
    admin = (ROOT / 'src/core/enrollment_admin.cpp').read_text()
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    for marker in ('lifecycle_magic', 'lifecycle_record_size', 'active->pin != expected',
                   'active->retired = true', 'Status::Revoked', 'session.abort()',
                   'Status::Full', 'publish(dir.value, data)'):
        require(marker in registry, f'missing lifecycle control: {marker}')
    for marker in ('X509_cmp_current_time', 'X509_get0_notBefore', 'X509_get0_notAfter',
                   'SSL_get0_peer_certificate', 'SSL_get_certificate', 'trust_anchor.get()',
                   'revalidate_peer'):
        require(marker in tls, f'missing TLS validity control: {marker}')
    for marker in ('operation == "rotate"', 'operation == "revoke"'):
        require(marker in admin, f'missing administrative operation: {marker}')
    name = 'knetsentry_credential_lifecycle'
    require(name in CORE_TESTS and f'NAME {name}' in tests, 'missing mandatory lifecycle regression')
    require('CREDENTIAL_LIFECYCLE_M45.md' in (ROOT / 'docs/README.md').read_text(), 'missing Wiki index')
    print('M4.5 credential lifecycle source contract: PASS (compiled tests separate)')


if __name__ == '__main__':
    main()

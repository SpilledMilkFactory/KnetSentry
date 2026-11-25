#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M4.2 source-only identity and dependency boundary contract."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def require(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError(label)


def main() -> None:
    source = (ROOT / 'src/core/identity.cpp').read_text()
    header = (ROOT / 'include/knetsentry/core/identity.hpp').read_text()
    cmake = (ROOT / 'src/core/CMakeLists.txt').read_text()
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    contract = (ROOT / 'docs/development/IDENTITY_M42.md').read_text()
    for marker in ('EVP_PKEY_Q_keygen', 'EVP_Digest', 'OPENSSL_cleanse', 'O_NOFOLLOW',
                   'O_EXCL', 'O_NONBLOCK', 'linkat(', 'fsync(', 'X509_verify_cert',
                   'X509_V_FLAG_X509_STRICT', 'X509_STORE_add_cert', 'CRYPTO_memcmp'):
        require(marker in source, f'identity control missing {marker}')
    for forbidden in ('X509_STORE_set_default_paths', 'SSL_connect', 'socket(', 'system('):
        require(forbidden not in source, f'unapproved identity boundary {forbidden}')
    require('max_key_bytes = 1024' in header and 'max_certificate_bytes = 8192' in header,
            'missing bounded inputs')
    require('find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)' in cmake and
            'target_link_libraries(knetsentry_identity PUBLIC OpenSSL::Crypto)' in cmake and
            'knetsentry_apply_project_options(knetsentry_identity)' in cmake,
            'missing scoped identity dependency')
    for relative in ('apps/manager/CMakeLists.txt', 'apps/desktop/CMakeLists.txt', 'src/service/CMakeLists.txt'):
        require('KnetSentry::Identity' not in (ROOT / relative).read_text(), 'operational linkage premature')
    require('NAME knetsentry_identity_contract' in tests and
            'knetsentry_apply_project_options(knetsentry_identity_test)' in tests and
            'knetsentry_identity_contract' in CORE_TESTS, 'mandatory regression missing')
    require('IDENTITY_M42.md' in (ROOT / 'docs/README.md').read_text(), 'Wiki index missing')
    for marker in ('DEP-005', 'TH-007', 'TH-040', 'TV-06', 'KS-NET-011', 'not APPROVED_FOR_DISTRIBUTION'):
        require(marker in contract, f'identity contract missing {marker}')
    print('M4.2 identity and scoped dependency source contract: PASS (compiled tests separate)')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline M4.3 TLS source contract; compiled handshake tests are separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> None:
    source = (ROOT / 'src/core/tls_transport.cpp').read_text()
    header = (ROOT / 'include/knetsentry/core/tls_transport.hpp').read_text()
    cmake = (ROOT / 'src/core/CMakeLists.txt').read_text()
    for marker in ('TLS1_3_VERSION', 'SSL_VERIFY_FAIL_IF_NO_PEER_CERT',
                   'SSL_CTX_set_cert_verify_callback', 'identity::validate_certificate',
                   'X509_verify_cert', 'SSL_CTX_set_num_tickets(ctx, 0)',
                   'SSL_CTX_set_max_early_data(ctx, 0)', 'SSL_SESS_CACHE_OFF',
                   'SSL_session_reused', 'selected_alpn', 'SSL3_MT_CERTIFICATE_VERIFY',
                   'local_proof_sent', 'BIO_new_bio_pair',
                   'SSL_do_handshake', 'SSL_shutdown', 'OPENSSL_cleanse'):
        require(marker in source, f'missing TLS control: {marker}')
    for forbidden in ('SSL_VERIFY_NONE', 'SSL_CTX_set_default_verify_paths', 'socket(', 'connect(', 'listen('):
        require(forbidden not in source, f'unapproved transport behavior: {forbidden}')
    for marker in ('max_plaintext = 4096', 'max_ciphertext_chunk = 16384',
                   'wire_buffer_bytes = 65536', 'max_handshake_input = 262144'):
        require(marker in header, f'missing bounds: {marker}')
    require('COMPONENTS Crypto SSL' in cmake and 'OPENSSL_SSL_LIBRARY MATCHES' in cmake and
            'KnetSentry::Identity OpenSSL::SSL' in cmake and
            'knetsentry_apply_project_options(knetsentry_tls)' in cmake, 'TLS build boundary')
    for path in ('apps/manager/CMakeLists.txt', 'apps/desktop/CMakeLists.txt', 'src/service/CMakeLists.txt'):
        require('KnetSentry::Tls' not in (ROOT / path).read_text(), 'premature operational linkage')
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    require('knetsentry_tls_contract' in CORE_TESTS and 'NAME knetsentry_tls_contract' in tests and
            'knetsentry_apply_project_options(knetsentry_tls_test)' in tests, 'mandatory test absent')
    require('TLS_TRANSPORT_M43.md' in (ROOT / 'docs/README.md').read_text(), 'missing Wiki index')
    print('M4.3 bounded mutually authenticated TLS source contract: PASS (compiled tests separate)')


if __name__ == '__main__':
    main()

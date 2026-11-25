#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline enrollment integration contract; compiled regressions are separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def require(condition, label):
    if not condition:
        raise ValueError(label)


def main():
    source = (ROOT / 'src/core/enrollment.cpp').read_text() + (ROOT / 'src/core/enrollment_admission.cpp').read_text()
    tls = (ROOT / 'src/core/tls_transport.cpp').read_text()
    admin = (ROOT / 'src/core/enrollment_admin.cpp').read_text()
    cmake = (ROOT / 'src/core/CMakeLists.txt').read_text()
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    for marker in ('O_NOFOLLOW', 'O_EXCL', 'LOCK_EX | LOCK_NB', 'fsync(dir)',
                   'renameat(', 'unlinkat(', 'st_nlink == 1', 'Status::Conflict',
                   'Status::Full', 'Status::Unavailable', 'session.authenticated_agent()',
                   'approved.pin == proof', 'endpoints.v1.pending'):
        require(marker in source, f'enrollment control missing: {marker}')
    for marker in ('State::Trusted', 'Role::Agent', 'impl_->peer_verified'):
        require(marker in tls, f'TLS admission proof missing: {marker}')
    for marker in ('operation == "init"', 'operation == "approve"', 'O_NOFOLLOW'):
        require(marker in admin, f'administrator operation missing: {marker}')
    for forbidden in ('socket(', 'connect(', 'listen(', 'system('):
        require(forbidden not in source and forbidden not in admin, f'unapproved operation: {forbidden}')
    for marker in ('KnetSentry::Enrollment', 'knetsentry_apply_project_options(knetsentry_enrollment)',
                   'knetsentry_apply_project_options(knetsentry-enrollment)'):
        require(marker in cmake, f'build control missing: {marker}')
    for name in ('knetsentry_enrollment_contract', 'knetsentry_enrollment_admin'):
        require(name in CORE_TESTS and f'NAME {name}' in tests, f'missing mandatory test {name}')
    for path in ('apps/manager/CMakeLists.txt', 'apps/desktop/CMakeLists.txt', 'src/service/CMakeLists.txt'):
        require('KnetSentry::Enrollment' not in (ROOT / path).read_text(), 'premature production linkage')
    require('ENDPOINT_ENROLLMENT_M44.md' in (ROOT / 'docs/README.md').read_text(), 'Wiki index missing')
    print('M4.4 offline explicit enrollment source contract: PASS (compiled tests separate)')


if __name__ == '__main__':
    main()

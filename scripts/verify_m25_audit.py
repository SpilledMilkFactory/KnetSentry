#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M2.5 source contract and optional compiled/live verification."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding='utf-8')


def source_contract() -> None:
    implementation = read('src/service/audit.cpp')
    header = read('include/knetsentry/service/audit.hpp')
    ipc = read('src/service/local_ipc.cpp')
    manager = read('apps/manager/main.cpp')
    for token in ('O_EXCL', 'O_APPEND', 'O_NOFOLLOW', 'O_CLOEXEC', '0700U', '0600U',
                  'st_nlink == 1', 'getrandom', '::fsync(dir)', '::fsync(fd_)',
                  'max_bytes - bytes_', 'failed_ = true', 'safe_file(fd_, bytes_)'):
        require(token in implementation, f'audit guard missing: {token}')
    for token in ('max_bytes = 1024U * 1024U', 'max_record = 512', 'AuditEvent', 'AuditActor'):
        require(token in header, f'audit bound/type missing: {token}')
    require('request_id' not in implementation and 'std::string_view message' not in header,
            'arbitrary request text must not be accepted by audit writer')
    require(ipc.index('::getsockopt(client, SOL_SOCKET, SO_PEERCRED') <
            ipc.index('audit.record(is_health'), 'audit must follow peer authentication')
    require(ipc.index('audit.record(is_health') < min(ipc.index('const auto snapshot'), ipc.index('const auto roster =')),
            'authorization must be committed before response')
    for token in ('AuditEvent::AuthenticationFailed', 'AuditEvent::AdministrativeDenied',
                  'AuditEvent::TransportFailed', 'if (!audit.ok())'):
        require(token in ipc, f'IPC audit hook missing: {token}')
    for token in ('--audit-dir', 'audit.open(audit_dir)', 'AuditEvent::ConfigRejected',
                  'AuditEvent::ConfigValidated', 'return 6;', 'SIGXFSZ'):
        require(token in manager, f'manager audit hook missing: {token}')
    require(manager.index('audit.open(audit_dir)') < manager.index('lifecycle.mark_ready()'),
            'audit must open before readiness')
    require('audit.cpp' in read('src/service/CMakeLists.txt'), 'audit library missing')
    for name in ('knetsentry_service_audit_contract', 'knetsentry_service_audit_runtime'):
        require(f'NAME {name}' in read('tests/CMakeLists.txt') and
                f'"{name}"' in read('scripts/verify_m17_suites.py'), f'missing test {name}')
    for token in ('TB-05', 'TB-07', 'I-21', 'TH-033', '1 MiB', 'exit 6'):
        require(token in read('docs/development/SERVICE_AUDIT_M25.md'), f'missing doc: {token}')
    print('M2.5 audit source contract: PASS (typed, bounded, protected, fail-closed)')
    print('  Source-only: actual filesystem durability and runtime authorization NOT verified')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    try:
        source_contract()
        if args.build_dir:
            build = args.build_dir.resolve()
            subprocess.run([str(build / 'tests/knetsentry_service_audit_test')],
                           check=True, timeout=60)
            subprocess.run([sys.executable, str(ROOT / 'scripts/check_m25_audit_runtime.py'),
                            '--binary', str(build / 'apps/manager/knetsentryd')],
                           check=True, timeout=60)
            print('M2.5 compiled and live audit: PASS')
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f'M2.5 audit verification: FAIL: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

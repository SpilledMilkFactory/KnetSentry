#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M2.3 source/security contract; --build-dir also runs real AF_UNIX tests."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding='utf-8')


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def source_contract() -> None:
    header = read('include/knetsentry/service/local_ipc.hpp')
    impl = read('src/service/local_ipc.cpp')
    manager = read('apps/manager/main.cpp')
    cmake = read('src/service/CMakeLists.txt')
    tests = read('tests/CMakeLists.txt')
    inventory = read('scripts/verify_m17_suites.py')
    docs = read('docs/development/LOCAL_AUTHENTICATED_IPC_M23.md')
    for piece in ('AF_UNIX', 'SO_PEERCRED', 'SOCK_CLOEXEC', 'O_NOFOLLOW',
                  '0700', '0600', 'SOCK_NONBLOCK', 'AT_SYMLINK_NOFOLLOW',
                  'MSG_NOSIGNAL', 'MSG_DONTWAIT', 'max_frame_size = 64',
                  'client_deadline_ms = 250', 'SOCK_STREAM',
                  'authorize_local_peer', 'IpcAction::Status',
                  'peer.pid <= 0', 'signalfd', 'POLLIN', 'SFD_NONBLOCK',
                  'KSIPC/1 STATUS', 'LIFECYCLE_ONLY'):
        require(piece in impl, f'IPC security feature missing: {piece}')
    for piece in ('peer_uid == service_uid', 'peer_gid == service_gid',
                  'action == IpcAction::Status'):
        require(piece in impl, f'default-deny authorization rule missing: {piece}')
    for piece in ('LocalIpcServer', 'IpcAction', 'authorize_local_peer'):
        require(piece in header, f'public IPC boundary missing: {piece}')
    require('local_ipc.cpp' in cmake and 'knetsentry_apply_project_options' in cmake,
            'IPC must link to hardened Qt-independent service library')
    for piece in ('--ipc-dir', 'ipc.open(ipc_dir, stop_signals)', 'ipc.serve(lifecycle, health)',
                  'ManagerReady', 'local IPC unavailable (no fallback)'):
        require(piece in manager, f'daemon does not enforce IPC startup: {piece}')
    require(manager.index('ipc.open(ipc_dir, stop_signals)') < manager.index('lifecycle.mark_ready()'),
            'manager must bind a safe IPC endpoint before claiming ready')
    for name in ('knetsentry_local_ipc_authorization_contract',
                 'knetsentry_local_ipc_runtime'):
        require(f'NAME {name}' in tests and f'"{name}"' in inventory,
                f'IPC test absent from required CTest inventory: {name}')
    require('check_m23_ipc_runtime.py' in tests and 'service_ipc_m23.cpp' in tests,
            'compiled peer authorization and real-process IPC tests mandatory')
    for piece in ('TB-05', 'I-01', 'SO_PEERCRED', 'same UID', 'no TCP',
                  'read-only', '0600', '0700', 'M2.4', 'M2.8',
                  'same-user', 'unauthorized', 'not', 'limits'):
        require(piece.lower() in docs.lower(), f'missing IPC documentation: {piece}')
    require('Qt6' not in impl and 'KF6' not in impl and 'AF_INET' not in impl,
            'service IPC must remain Qt-independent and AF_UNIX-only')
    print('M2.3 local IPC source contract: PASS (peer credentials, permissions, bounds, deny-by-default)')
    print('  Source-only: not evidence of actual kernel peer-auth behavior')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    try:
        source_contract()
        if args.build_dir:
            manager = args.build_dir.resolve() / 'apps/manager/knetsentryd'
            require(manager.is_file(), 'compiled management daemon unavailable')
            command = [sys.executable, str(ROOT / 'scripts/check_m23_ipc_runtime.py'),
                       '--binary', str(manager)]
            result = subprocess.run(command, timeout=55, check=False)
            require(result.returncode == 0, 'real IPC negative tests did not pass')
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'M2.3 local IPC verification: FAIL: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

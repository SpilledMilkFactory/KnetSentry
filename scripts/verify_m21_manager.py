#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M2.1 source policy plus optional executed daemon verification.

Source-only PASS is never proof of functional daemon/signal behavior.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding='utf-8')


def source_contract() -> None:
    root = read('CMakeLists.txt')
    manager_cmake = read('apps/manager/CMakeLists.txt')
    service_cmake = read('src/service/CMakeLists.txt')
    main = read('apps/manager/main.cpp')
    lifecycle = read('src/service/lifecycle.cpp')
    header = read('include/knetsentry/service/lifecycle.hpp')
    tests = read('tests/CMakeLists.txt')
    diag = read('src/core/diagnostics.cpp')
    docs = read('docs/development/MANAGER_DAEMON_M21.md')
    inventory = read('scripts/verify_m17_suites.py')

    for piece in ('add_subdirectory(src/service)', 'add_subdirectory(apps/manager)'):
        require(piece in root, f'daemon target omitted: {piece}')
    for piece in ('add_executable(knetsentryd main.cpp)',
                  'KnetSentry::Core KnetSentry::Service Threads::Threads',
                  'knetsentry_apply_project_options(knetsentryd)'):
        require(piece in manager_cmake, f'daemon build contract missing: {piece}')
    require('Qt6::' not in manager_cmake and 'KF6' not in manager_cmake,
            'manager must not depend on GUI')
    require('knetsentry_apply_project_options(knetsentry_service)' in service_cmake,
            'state machine must use project hardening')
    for piece in ('Created', 'Starting', 'Running', 'Stopping', 'Stopped', 'Failed'):
        require(piece in header, f'missing lifecycle state {piece}')
    for piece in ('state_ != State::Created', 'state_ != State::Starting',
                  'state_ != State::Stopping', 'State::Stopped || state_ == State::Failed'):
        require(piece in lifecycle, f'missing transition guard {piece}')
    for piece in ('pthread_sigmask(SIG_BLOCK', 'sigwait(&stop_signals',
                  'SIGTERM', 'SIGINT', 'geteuid() == 0', 'ManagerStarting',
                  'ManagerReady', 'ManagerStopping', 'ManagerStopped',
                  'ManagerFailed', 'return 3;', 'return 2;'):
        require(piece in main, f'missing signal/security contract: {piece}')
    for forbidden in ('socket(', 'bind(', 'listen(', 'connect(', 'system(',
                      'setuid(', 'setgid(', 'fork(', 'daemon(', 'QApplication',
                      'QQmlApplicationEngine'):
        require(forbidden not in main, f'premature daemon capability: {forbidden}')
    for label in ('manager_starting', 'manager_ready', 'manager_stopping',
                  'manager_stopped', 'manager_failed'):
        require(f'"{label}"' in diag, f'non-allowlisted diagnostic event: {label}')
    for name in ('knetsentry_manager_state_contract',
                 'knetsentry_manager_signal_lifecycle'):
        require(f'NAME {name}' in tests and f'"{name}"' in inventory,
                f'M2.1 CTest missing from registration/inventory: {name}')
    require('check_m21_manager_runtime.py' in tests,
            'real daemon signal test not registered')
    for required in ('TB-05', 'non-authoritative', 'No raw-event',
                     'not implemented', 'SIGTERM', 'SIGINT', '15', '12', '7', '8'):
        require(required.lower() in docs.lower(),
                f'manager document missing scope/qualification: {required}')
    print('M2.1 manager source contract: PASS (independent daemon, signal and root gates)')
    print('  Lifecycle state guards and fixed diagnostic events verified')
    print('  Source-only: actual daemon process, signals and hardening NOT verified')


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build-dir', type=Path)
    args = p.parse_args()
    try:
        source_contract()
        if args.build_dir:
            binary = (args.build_dir.resolve() / 'apps/manager/knetsentryd')
            require(binary.is_file(), f'missing compiled manager: {binary}')
            cmd = [sys.executable, str(ROOT / 'scripts/check_m21_manager_runtime.py'),
                   '--binary', str(binary)]
            completed = subprocess.run(cmd, check=False, timeout=40)
            require(completed.returncode == 0, 'compiled manager process failed')
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'M2.1 manager verification: FAIL: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

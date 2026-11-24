#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M2.4 source contract; optional build directory runs compiled and live tests."""
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
    header = read('include/knetsentry/service/health.hpp')
    impl = read('src/service/health.cpp')
    ipc = read('src/service/local_ipc.cpp')
    manager = read('apps/manager/main.cpp')
    docs = read('docs/development/SERVICE_HEALTH_M24.md')
    for token in ('max_health_response_size = 256', 'HealthTracker', 'HealthSnapshot'):
        require(token in header, f'health contract missing: {token}')
    for token in ('steady_clock', 'getrusage(RUSAGE_SELF', 'ru_maxrss', 'cpu_time_ms',
                  'saturating_increment', 'std::to_chars', 'State::Running', '"NA"',
                  'MONITORING_UNAVAILABLE'):
        require(token in impl, f'health implementation missing: {token}')
    for token in ('SO_PEERCRED', 'max_frame_size = 64', 'KSIPC/1 HEALTH',
                  'IpcAction::Health', 'authorize_local_peer', 'HealthError::Rejected',
                  'HealthError::Transport', 'health.sample(lifecycle.state())'):
        require(token in ipc, f'IPC integration missing: {token}')
    require(ipc.index('::getsockopt(client, SOL_SOCKET, SO_PEERCRED') <
            ipc.index('health.sample(lifecycle.state())'), 'sampling must follow authentication')
    require('ipc.serve(lifecycle, health)' in manager and 'health.cpp' in
            read('src/service/CMakeLists.txt'), 'manager integration missing')
    for name in ('knetsentry_service_health_contract', 'knetsentry_service_health_runtime'):
        require(f'NAME {name}' in read('tests/CMakeLists.txt') and
                f'"{name}"' in read('scripts/verify_m17_suites.py'), f'missing test {name}')
    for token in ('TB-05', 'I-01', 'KS-NET-012', 'TH-010', 'TH-038', 'NA', 'peak_rss_kib'):
        require(token in docs, f'missing documentation: {token}')
    print('M2.4 service health source contract: PASS (bounded, typed, authorized)')
    print('  Source-only: actual resource sampling and kernel authorization NOT verified')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    try:
        source_contract()
        if args.build_dir:
            build = args.build_dir.resolve()
            binary = build / 'tests/knetsentry_service_health_test'
            manager = build / 'apps/manager/knetsentryd'
            require(binary.is_file() and manager.is_file(), 'compiled tests or daemon unavailable')
            subprocess.run([str(binary)], check=True, timeout=10)
            subprocess.run([sys.executable, str(ROOT / 'scripts/check_m24_health_runtime.py'),
                            '--binary', str(manager)], check=True, timeout=60)
            print('M2.4 compiled health and live IPC: PASS')
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'M2.4 health verification: FAIL: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

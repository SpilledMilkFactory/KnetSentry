#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M2.2 source contract, optionally with actual compiled daemon verification."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def require(ok: bool, why: str) -> None:
    if not ok:
        raise ValueError(why)


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding='utf-8')


def source_contract() -> None:
    header = read('include/knetsentry/service/configuration.hpp')
    impl = read('src/service/configuration.cpp')
    service_build = read('src/service/CMakeLists.txt')
    manager = read('apps/manager/main.cpp')
    tests = read('tests/CMakeLists.txt')
    inventory = read('scripts/verify_m17_suites.py')
    docs = read('docs/development/MANAGER_CONFIGURATION_M22.md')
    for field in ('schema_version', 'mode', 'monitoring_enabled',
                  'network_listeners_enabled', 'packet_capture_enabled',
                  'public_intelligence_enabled', 'privileged_actions_enabled'):
        require(field in header and field in impl, f'missing typed field: {field}')
    for rule in ('O_NOFOLLOW', 'O_NONBLOCK', 'O_CLOEXEC',
                 'S_ISREG', 'st_uid != ::geteuid()', 'st_nlink != 1',
                 'max_bytes = 4096', 'max_lines = 32', 'same_identity',
                 'ConfigurationError::DuplicateField',
                 'ConfigurationError::UnknownField',
                 'ConfigurationError::UnsupportedVersion',
                 'ConfigurationError::UnsafeSetting'):
        require(rule in impl, f'missing fail-closed parser rule: {rule}')
    require('configuration.cpp' in service_build and
            'knetsentry_apply_project_options(knetsentry_service)' in service_build,
            'config library must receive first-party hardening')
    for rule in ('--config', '--check-config', 'load_configuration(',
                 'ManagerFailed', 'configuration rejected (no fallback)'):
        require(rule in manager, f'manager integration missing: {rule}')
    require(manager.index('load_configuration(configuration_path)') <
            manager.index('lifecycle.mark_ready()'),
            'daemon must verify config BEFORE declaring readiness')
    for name in ('knetsentry_manager_configuration_contract',
                 'knetsentry_manager_configuration_runtime'):
        require(f'NAME {name}' in tests and f'"{name}"' in inventory,
                f'configuration regression CTest unregistered: {name}')
    require('check_m22_config_runtime.py' in tests and
            'service_configuration_m22.cpp' in tests,
            'both compiled and real-daemon security tests are required')
    require('Qt6' not in impl and 'Qt6' not in header and 'KF6' not in impl,
            'management configuration must not depend on GUI libraries')
    for phrase in ('version', '0600', 'no fallback', 'TB-05',
                   'lifecycle only', 'raw-event', 'no network'):
        require(phrase.lower() in docs.lower(), f'documentation contract missing: {phrase}')
    print('M2.2 configuration source contract: PASS (versioned, bounded, fail-closed)')
    print('  Source-only: no compiled or hosted acceptance implied')


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--build-dir', type=Path)
    args = p.parse_args()
    try:
        source_contract()
        if args.build_dir is not None:
            binary = args.build_dir.resolve() / 'apps/manager/knetsentryd'
            require(binary.is_file(), f'missing compiled manager: {binary}')
            result = subprocess.run([sys.executable,
                str(ROOT / 'scripts/check_m22_config_runtime.py'), '--binary', str(binary)],
                check=False, timeout=55)
            require(result.returncode == 0, 'compiled configured daemon failed')
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f'M2.2 configuration verification: FAIL: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

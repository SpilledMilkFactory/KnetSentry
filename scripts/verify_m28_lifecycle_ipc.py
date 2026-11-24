#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M2.8 source registration and optional configured lifecycle test execution."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

from verify_m17_suites import ROOT, CORE_TESTS, configured_contract, require

NAME = 'knetsentry_service_lifecycle_ipc_integration'


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    registration = tests.index('add_test(NAME ' + NAME)
    require(NAME in CORE_TESTS and registration < tests.index('if(KNETSENTRY_BUILD_DESKTOP)'),
            'lifecycle integration must be mandatory in core and desktop presets')
    block = tests[registration:tests.index('if(KNETSENTRY_BUILD_DESKTOP)')]
    for token in ('check_m28_lifecycle_ipc.py', '$<TARGET_FILE:knetsentryd>',
                  '$<TARGET_FILE:knetsentry_health_client_test>', 'TIMEOUT 90',
                  'integration;security;ipc;service;privacy;regression'):
        require(token in block, 'missing CTest contract: ' + token)
    require('SERVICE_LIFECYCLE_IPC_M28.md' in (ROOT / 'README.md').read_text(),
            'missing lifecycle documentation link')
    require('knetsentry_gui_health_runtime' in tests and 'knetsentry_systemd_policy_contract' in tests,
            'earlier GUI or systemd regression missing')
    print('M2.8 lifecycle IPC registration and documentation: PASS (source-only)', flush=True)
    if args.build_dir:
        configured_contract(args.build_dir.resolve())
        subprocess.run(['ctest', '--test-dir', str(args.build_dir.resolve()),
                        '-R', '^' + NAME + '$', '--verbose', '--no-tests=error'],
                       check=True, timeout=110)
        print('M2.8 configured lifecycle IPC integration: PASS')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Verify M3.3 source registration and optionally run compiled topology tests."""
import argparse
import contextlib
import io
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

# Avoid writing bytecode to the source tree during policy verification.
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
TEST = 'knetsentry_network_topology_awareness'


def verify_namespace_outcomes() -> None:
    from check_m33_topology_namespace import (
        BLOCKED, COMPLETED, ENTERED, FAIL, PASS, SETUP_DENIALS,
        classify_namespace_result, launch_namespace,
    )
    denial = 'unshare: write failed /proc/self/uid_map: Operation not permitted\n'
    def result(code, out='', err=''):
        return subprocess.CompletedProcess(['unshare'], code, out, err)

    fixtures = [
        (result(0, f'{ENTERED}\nfixture PASS\n{COMPLETED}\n'), PASS),
        (result(1, err=denial), BLOCKED),
        (result(1, f'{ENTERED}\n', denial), FAIL),
        (result(1, err='ip: Operation not permitted\n'), FAIL),
        (result(1, err=denial + 'unexpected error\n'), FAIL),
        (result(77, err=denial), FAIL),
        (result(-9, err=denial), FAIL),
        (result(0), FAIL),
        (result(0, f'{ENTERED}\n'), FAIL),
        (result(0, f'{COMPLETED}\n'), FAIL),
        (result(1, f'{ENTERED}\n{COMPLETED}\n'), FAIL),
        (result(0, f'{ENTERED}\n{ENTERED}\n{COMPLETED}\n'), FAIL),
    ]
    fixtures.extend((result(1, err=message + '\n'), BLOCKED)
                    for message in SETUP_DENIALS)
    for response, expected in fixtures:
        if classify_namespace_result(response) != expected:
            raise ValueError('M3.3 namespace exit classification regression')
    # Exercise the launcher contract with mocked subprocesses only. Never
    # create namespaces or run mutation fixtures during source verification.
    binary = Path('/synthetic/knetsentry_network_topology_test')
    with patch('check_m33_topology_namespace.os.geteuid', return_value=1000), \
         patch('check_m33_topology_namespace.shutil.which', return_value=None), \
         patch('check_m33_topology_namespace.subprocess.run') as runner, \
         contextlib.redirect_stderr(io.StringIO()):
        if launch_namespace(binary) != BLOCKED or runner.called:
            raise ValueError('missing namespace tool did not block safely')
    with patch('check_m33_topology_namespace.os.geteuid', return_value=0), \
         patch('check_m33_topology_namespace.subprocess.run') as runner:
        try:
            launch_namespace(binary)
        except RuntimeError:
            pass
        else:
            raise ValueError('root namespace launch was not refused')
        if runner.called:
            raise ValueError('root attempted namespace creation')
    print('M3.3 namespace outcome fixtures: PASS (no actual namespace mutation)', flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    checks = {
        'src/core/CMakeLists.txt': ('linux_topology.cpp',),
        'tests/CMakeLists.txt': (f'NAME {TEST}', 'knetsentry_apply_project_options(knetsentry_network_topology_test)'),
        'scripts/verify_m17_suites.py': (f'"{TEST}"',),
        'src/core/linux_topology.cpp': ('RTM_GETLINK', 'RTM_GETROUTE', 'RTM_F_FIB_MATCH',
                                       'NETLINK_ADD_MEMBERSHIP', 'TopologyState::Invalidated'),
        'include/knetsentry/core/linux_topology.hpp': ('check_changes', 'TopologyResult'),
        'README.md': ('NETWORK_TOPOLOGY_M33.md',),
    }
    for path, tokens in checks.items():
        source = (ROOT / path).read_text(encoding='utf-8')
        if not all(token in source for token in tokens):
            raise ValueError('missing M3.3 source registration: ' + path)
    print('M3.3 network topology source registration: PASS (runtime not verified)', flush=True)
    verify_namespace_outcomes()
    if args.build_dir:
        from verify_m17_suites import configured_contract
        configured_contract(args.build_dir.resolve())
        subprocess.run(['ctest', '--test-dir', str(args.build_dir.resolve()), '-R',
                        '^' + TEST + '$', '--verbose', '--no-tests=error'], check=True, timeout=45)
        print('M3.3 configured network topology awareness: PASS')


if __name__ == '__main__':
    main()

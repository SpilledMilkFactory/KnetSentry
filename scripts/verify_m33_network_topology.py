#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Verify M3.3 source registration and optionally run compiled topology tests."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
TEST = 'knetsentry_network_topology_awareness'


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
    if args.build_dir:
        from verify_m17_suites import configured_contract
        configured_contract(args.build_dir.resolve())
        subprocess.run(['ctest', '--test-dir', str(args.build_dir.resolve()), '-R',
                        '^' + TEST + '$', '--verbose', '--no-tests=error'], check=True, timeout=45)
        print('M3.3 configured network topology awareness: PASS')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Verify M3.4 registration and optionally run the compiled fail-closed test."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
TEST = 'knetsentry_network_fail_closed_authorization'


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    checks = {
        'src/core/CMakeLists.txt': ('network_authorization.cpp',),
        'tests/CMakeLists.txt': (f'NAME {TEST}', 'knetsentry_apply_project_options(knetsentry_network_authorization_test)'),
        'scripts/verify_m17_suites.py': (f'"{TEST}"',),
        'include/knetsentry/core/network_authorization.hpp': ('ConfigurationEvidence', 'high_water_generation', 'candidate_in_scope'),
        'src/core/network_authorization.cpp': ('topology_->evaluate', 'topology_->check_changes', 'TopologyInvalidated',
                                                'RouteUnverified', 'StaleGeneration'),
        'docs/README.md': ('NETWORK_AUTHORIZATION_M34.md',),
    }
    for path, tokens in checks.items():
        source = (ROOT / path).read_text(encoding='utf-8')
        if not all(token in source for token in tokens):
            raise ValueError('missing M3.4 source registration: ' + path)
    print('M3.4 fail-closed network authorization source registration: PASS (runtime not verified)', flush=True)
    if args.build_dir:
        from verify_m17_suites import configured_contract
        configured_contract(args.build_dir.resolve())
        subprocess.run(['ctest', '--test-dir', str(args.build_dir.resolve()), '-R',
                        '^' + TEST + '$', '--verbose', '--no-tests=error'], check=True, timeout=45)
        print('M3.4 configured fail-closed network authorization: PASS')


if __name__ == '__main__':
    main()

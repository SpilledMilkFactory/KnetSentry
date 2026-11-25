#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Verify M3.1 source registration and optionally run the compiled policy test."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
TEST = 'knetsentry_network_scope_policy'


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    checks = {
        'src/core/CMakeLists.txt': ('network_scope.cpp',),
        'tests/CMakeLists.txt': (f'NAME {TEST}', 'knetsentry_apply_project_options(knetsentry_network_scope_test)'),
        'scripts/verify_m17_suites.py': (f'"{TEST}"',),
        'include/knetsentry/core/network_scope.hpp': ('CandidateInScope', 'max_approvals', 'RouteEvidence'),
        'docs/README.md': ('NETWORK_SCOPE_POLICY_M31.md',),
    }
    for path, tokens in checks.items():
        source = (ROOT / path).read_text(encoding='utf-8')
        if not all(token in source for token in tokens):
            raise ValueError('missing M3.1 source registration: ' + path)
    print('M3.1 network scope source registration: PASS (runtime not verified)', flush=True)
    if args.build_dir:
        from verify_m17_suites import configured_contract
        configured_contract(args.build_dir.resolve())
        subprocess.run(['ctest', '--test-dir', str(args.build_dir.resolve()), '-R',
                        '^' + TEST + '$', '--verbose', '--no-tests=error'], check=True, timeout=45)
        print('M3.1 configured network scope policy: PASS')


if __name__ == '__main__':
    main()

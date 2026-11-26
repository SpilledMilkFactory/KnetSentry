#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline FIM registration and source contract; runtime qualification separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_file_integrity_contract'
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    source = (ROOT / 'src/agent/fim.cpp').read_text()
    if name not in CORE_TESTS or f'NAME {name}' not in tests:
        raise ValueError('missing mandatory M5.6 regression')
    for marker in ('SYS_openat2', 'RESOLVE_NO_SYMLINKS', 'RESOLVE_NO_MAGICLINKS',
                   'RESOLVE_NO_XDEV', 'O_PATH', 'EVP_sha256()', 'safe_file', 'parent_matches'):
        if marker not in source:
            raise ValueError('missing FIM control: ' + marker)
    if 'FILE_INTEGRITY_M56.md' not in (ROOT / 'docs/README.md').read_text():
        raise ValueError('missing documentation index')
    if 'KnetSentry::AgentFIM' not in (ROOT / 'apps/agent/CMakeLists.txt').read_text():
        raise ValueError('missing FIM agent linkage')
    print('M5.6 explicit local FIM registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

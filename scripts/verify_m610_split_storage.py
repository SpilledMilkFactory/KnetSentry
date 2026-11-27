#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Source registration only; actual mount and persistence qualification is separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'src/agent/split_event_store.cpp': ('STATX_MNT_ID_UNIQUE', 'RESOLVE_NO_SYMLINKS', 'O_TMPFILE', 'linkat', 'fsync', 'sqlite3_serialize', 'sqlite3_deserialize', 'head_value', 'fstatvfs'),
        'src/agent/CMakeLists.txt': ('KnetSentry::SplitStorage', 'knetsentry_apply_project_options(knetsentry_split_storage)'),
        'tests/CMakeLists.txt': ('NAME knetsentry_split_storage_contract', 'knetsentry_apply_project_options(knetsentry_split_storage_test)'),
        'tests/split_storage_m610.cpp': ('CLONE_NEWNS', 'MNT_DETACH', 'RLIMIT_FSIZE', 'head_recovery'),
        'scripts/verify_m12_hardening.py': ('split_storage_m610.cpp', 'knetsentry_split_storage_test'),
        'docs/README.md': ('SPLIT_STORAGE_M610.md',),
    }
    for path, markers in checks.items():
        source = (ROOT / path).read_text(encoding='utf-8')
        for marker in markers:
            if marker not in source:
                raise ValueError(f'M6.10 missing {marker}: {path}')
    if 'knetsentry_split_storage_contract' not in CORE_TESTS:
        raise ValueError('M6.10 mandatory test missing')
    print('M6.10 split storage registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

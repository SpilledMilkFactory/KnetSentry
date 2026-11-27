#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Structural registration only; compiled detection regression is separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'include/knetsentry/detection/engine.hpp': ('max_rules = 64', 'EvidenceTrust', 'indeterminate', 'const;'),
        'src/agent/CMakeLists.txt': ('KnetSentry::Detection', 'knetsentry_apply_project_options(knetsentry_detection)'),
        'tests/CMakeLists.txt': ('NAME knetsentry_detection_contract', 'knetsentry_apply_project_options(knetsentry_detection_test)'),
        'scripts/verify_m12_hardening.py': ('detection_engine.cpp', 'detection_m71.cpp', 'knetsentry_detection_test'),
        'docs/README.md': ('DETECTION_ENGINE_M71.md',),
    }
    for name, markers in checks.items():
        source = (ROOT / name).read_text(encoding='utf-8')
        for marker in markers:
            if marker not in source:
                raise ValueError(f'M7.1 missing {marker}: {name}')
    if 'knetsentry_detection_contract' not in CORE_TESTS:
        raise ValueError('M7.1 mandatory test missing')
    print('M7.1 detection registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

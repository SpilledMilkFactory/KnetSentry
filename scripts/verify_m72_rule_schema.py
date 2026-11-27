#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Structural registration only; compiled rule validation is separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'include/knetsentry/detection/rule_schema.hpp': ('ValidatedRuleSet', 'RuleDiagnostic', 'schema_version = 1'),
        'src/agent/CMakeLists.txt': ('detection_engine.cpp rule_schema.cpp',),
        'src/agent/detection_engine.cpp': ('validate_predicate(rule)',),
        'tests/CMakeLists.txt': ('NAME knetsentry_rule_schema_contract', 'knetsentry_apply_project_options(knetsentry_rule_schema_test)'),
        'scripts/verify_m12_hardening.py': ('rule_schema.cpp', 'rule_schema_m72.cpp', 'knetsentry_rule_schema_test'),
        'docs/README.md': ('RULE_SCHEMA_M72.md',),
    }
    for name, markers in checks.items():
        source = (ROOT / name).read_text(encoding='utf-8')
        for marker in markers:
            if marker not in source:
                raise ValueError(f'M7.2 missing {marker}: {name}')
    if 'knetsentry_rule_schema_contract' not in CORE_TESTS:
        raise ValueError('M7.2 mandatory test missing')
    print('M7.2 rule schema registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

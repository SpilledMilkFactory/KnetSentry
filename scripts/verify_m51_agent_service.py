#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline registration; actual process qualification requires CTest."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    for name in ('knetsentry_agent_lifecycle_contract', 'knetsentry_agent_service_runtime'):
        if name not in CORE_TESTS or f'NAME {name}' not in tests:
            raise ValueError(f'missing mandatory test: {name}')
    cmake = (ROOT / 'apps/agent/CMakeLists.txt').read_text()
    if ('knetsentry_apply_project_options(knetsentry-agent)' not in cmake or
            'KnetSentry::AgentLifecycle' not in cmake or 'Qt6::' in cmake):
        raise ValueError('agent build boundary missing')
    if 'ENDPOINT_AGENT_SERVICE_M51.md' not in (ROOT / 'docs/README.md').read_text():
        raise ValueError('agent documentation not indexed')
    print('M5.1 endpoint-agent service registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

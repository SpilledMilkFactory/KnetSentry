#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline M4.6 source boundary; compiled TLS regression is separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    header = (ROOT / 'include/knetsentry/core/agent_health.hpp').read_text()
    source = (ROOT / 'src/core/agent_health.cpp').read_text()
    core = (ROOT / 'src/core/CMakeLists.txt').read_text()
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    for marker in ('heartbeat_interval = 30000', 'missing_after = 90000',
                   'attempt_timeout = 10000', 'maximum_retry = 60000', 'F_DUPFD_CLOEXEC'):
        require(marker in header + source, f'absent health bound: {marker}')
    for marker in ('enrollment::revalidate', 'session_->read', 'validator_->accept',
                   'protocol::inspect_header', 'session_.revalidate_peer', 'attempt != attempt_',
                   'now - last_report_ >= missing_after'):
        require(marker in source, f'absent health control: {marker}')
    require('KnetSentry::AgentHealth' in core and 'knetsentry_apply_project_options(knetsentry_agent_health)' in core,
            'missing isolated hardened target')
    for app in ('manager', 'desktop'):
        require('AgentHealth' not in (ROOT / f'apps/{app}/CMakeLists.txt').read_text(),
                'unexpected production linkage')
    name = 'knetsentry_agent_health_contract'
    require(name in CORE_TESTS and f'NAME {name}' in tests, 'missing mandatory regression')
    require('AGENT_HEALTH_M46.md' in (ROOT / 'docs/README.md').read_text(), 'missing Wiki index')
    print('M4.6 agent heartbeat and health source contract: PASS (compiled tests separate)')


if __name__ == '__main__':
    main()

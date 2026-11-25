#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M4.1 offline protocol source contract; compiled regressions run via CTest."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def require(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError(label)


def main() -> None:
    header = (ROOT / 'include/knetsentry/core/agent_protocol.hpp').read_text()
    source = (ROOT / 'src/core/agent_protocol.cpp').read_text()
    tests = (ROOT / 'tests/agent_protocol_m41.cpp').read_text()
    cmake = (ROOT / 'tests/CMakeLists.txt').read_text()
    contract = (ROOT / 'docs/development/AGENT_PROTOCOL_M41.md').read_text()
    for marker in ('header_size = 20', 'heartbeat_body_size = 16',
                   'major_version = 1', 'minor_version = 0', 'SessionValidator',
                   'inspect_header', 'noexcept'):
        require(marker in header, f'protocol declaration missing {marker}')
    for marker in ('Error::UnsupportedVersion', 'Error::UnsupportedKind',
                   'Error::Oversize', 'Error::InvalidSequence', 'Error::CounterRegression',
                   'Error::SessionClosed'):
        require(marker in source and marker in tests, f'missing error regression {marker}')
    for forbidden in ('sys/socket', 'QTcpSocket', 'connect(', 'send(', 'recv(', 'std::vector', 'std::string'):
        require(forbidden not in source and forbidden not in header, f'unexpected codec boundary {forbidden}')
    require('agent_protocol.cpp' in (ROOT / 'src/core/CMakeLists.txt').read_text(), 'codec not built')
    require('NAME knetsentry_agent_protocol_contract' in cmake and
            'knetsentry_apply_project_options(knetsentry_agent_protocol_test)' in cmake,
            'missing mandatory hardened test')
    from verify_m17_suites import CORE_TESTS
    require('knetsentry_agent_protocol_contract' in CORE_TESTS, 'test inventory missing protocol')
    for marker in ('I-07', 'TB-04', 'TH-008', 'TV-07', 'KS-NET-006', 'KS-NET-011',
                   'No downgrade', '36 bytes', 'cross-session replay'):
        require(marker in contract, f'contract missing {marker}')
    require('AGENT_PROTOCOL_M41.md' in (ROOT / 'docs/README.md').read_text(), 'Wiki index missing protocol')
    print('M4.1 bounded agent protocol source contract: PASS (compiled tests separate)')


if __name__ == '__main__':
    main()

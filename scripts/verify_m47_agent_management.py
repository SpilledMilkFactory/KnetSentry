#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Read-only agent management source contract; runtime qualification is separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return (ROOT / path).read_text()


def main():
    ipc = read('src/service/local_ipc.cpp')
    model = read('apps/desktop/service_health_model.hpp')
    page = read('apps/desktop/SectionPage.qml')
    for marker in ('IpcAction::Agents', 'enrollment::inspect(enrollment_fd_)',
                   'AuditEvent::AgentsAuthorized', 'set_enrollment_directory', 'O_NOFOLLOW'):
        require(marker in ipc, f'missing IPC control: {marker}')
    require('enrollment::approve' not in ipc and 'enrollment::revoke' not in ipc and
            'enrollment::rotate' not in ipc, 'administrative mutation in read-only IPC')
    require(ipc.index('audit.record(is_health') < ipc.index('enrollment::inspect'), 'audit must precede roster read')
    for name in ('agentRegistryStatus', 'approvedAgents', 'revokedAgents'):
        require(f'Q_PROPERTY(QString {name} READ {name} NOTIFY changed FINAL)' in model,
                f'missing read-only model property: {name}')
        require(f'description: page.healthModel.{name}' in page, f'missing actual binding: {name}')
    require('Q_INVOKABLE' not in model and 'WRITE ' not in model, 'mutable model')
    require('visible: page.sectionId === "assets"' in page, 'roster must be restricted to Assets')
    require('max_roster_response_size = 4608' in read('include/knetsentry/service/agent_roster.hpp'),
            'missing response bound')
    require('KnetSentry::Registry' in read('src/service/CMakeLists.txt'), 'missing isolated registry linkage')
    for name in ('knetsentry_agent_roster_contract', 'knetsentry_agent_roster_runtime'):
        require(name in CORE_TESTS and f'NAME {name}' in read('tests/CMakeLists.txt'), f'missing test: {name}')
    require('DESKTOP_AGENT_MANAGEMENT_M47.md' in read('docs/README.md'), 'missing Wiki index')
    print('M4.7 read-only enrollment roster source contract: PASS (runtime separate)')


if __name__ == '__main__':
    main()

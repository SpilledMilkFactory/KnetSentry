#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M5.9 source registration and minimized local presentation boundary."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS, NONSAN_DESKTOP_TESTS

ROOT = Path(__file__).resolve().parent.parent


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    agent = (ROOT / 'apps/agent/agent_main.cpp').read_text()
    status = (ROOT / 'include/knetsentry/agent/telemetry_status.hpp').read_text()
    model = (ROOT / 'apps/desktop/service_health_model.hpp').read_text()
    page = (ROOT / 'apps/desktop/SectionPage.qml').read_text()
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    require(agent.index('authorize_privacy(') < agent.index('status.attach(3)') < agent.index('make_journal_source('),
            'status must follow privacy validation and precede collector construction')
    for token in ('O_NONBLOCK', 'S_ISFIFO', 'F_DUPFD_CLOEXEC', 'SIGPIPE', 'status_fresh_ms = 5000',
                  'status_max_line = 160', 'parsed->stamp <= last_', 'StatusLink::Disconnected'):
        require(token in status, 'missing status boundary: ' + token)
    for name in ('Status', 'Collector', 'Health', 'Rate', 'Queue', 'Failure'):
        prop = 'telemetry' + name
        require(f'Q_PROPERTY(QString {prop} READ {prop} NOTIFY telemetryChanged FINAL)' in model,
                'missing read-only status property: ' + prop)
        require(f'description: page.healthModel.{prop}' in page, 'missing status card binding: ' + prop)
    require('Q_INVOKABLE' not in model and 'WRITE ' not in model, 'status model must be read-only')
    for name in ('knetsentry_telemetry_status_contract', 'knetsentry_telemetry_status_runtime'):
        require(name in CORE_TESTS and f'NAME {name}' in tests, 'missing core status test')
    name = 'knetsentry_gui_telemetry_runtime'
    require(name in NONSAN_DESKTOP_TESTS and f'NAME {name}' in tests, 'missing rendered status test')
    require('DESKTOP_TELEMETRY_STATUS_M59.md' in (ROOT / 'docs/README.md').read_text(), 'missing documentation index')
    print('M5.9 local aggregate status and read-only desktop registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

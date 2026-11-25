#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M2.6 source contract and optional configured health test execution."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding='utf-8')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    client = read('src/service/health_client.cpp')
    model = read('apps/desktop/service_health_model.cpp')
    header = read('apps/desktop/service_health_model.hpp')
    qml = read('apps/desktop/SectionPage.qml')
    main_cpp = read('apps/desktop/main.cpp')
    for token in ('SO_PEERCRED', 'SOCK_NONBLOCK', 'SOCK_CLOEXEC', 'AF_UNIX',
                  'std::chrono::seconds(2)', 'decode_health', 'std::from_chars',
                  'received_ > size + 4', 'count == 0'):
        require(token in client, 'client contract missing: ' + token)
    require(client.index('!verify_peer()') < client.index('::send(fd_'), 'peer gate ordering')
    for token in ('setInterval(30000)', 'setInterval(25)', 'geteuid() == 0', 'client_.begin'):
        require(token in model, 'model contract missing: ' + token)
    require('QML_UNCREATABLE' in header and 'Q_INVOKABLE' not in header and
            'WRITE ' not in header, 'model must be read-only')
    for token in ('page.healthModel.status', 'page.healthModel.resources',
                  'page.healthModel.errors', 'page.healthModel.components', 'Monitoring unavailable'):
        require(token in qml, 'QML health binding missing: ' + token)
    require('engine.setInitialProperties' in main_cpp and 'QQmlEngine::CppOwnership' in main_cpp,
            'explicit model lifetime/initialization missing')
    tests = read('tests/CMakeLists.txt')
    inventory = read('scripts/verify_m17_suites.py')
    for name in ('knetsentry_health_client_contract', 'knetsentry_health_client_runtime',
                 'knetsentry_qt_health_model', 'knetsentry_gui_health_runtime'):
        require(f'NAME {name}' in tests and f'"{name}"' in inventory, 'missing test: ' + name)
    require('Qt6::' not in read('src/service/CMakeLists.txt'), 'Qt leaked into service library')
    require('std::bit_cast<AuditEvent>' in read('tests/service_audit_m25.cpp'), 'audit negative fixture regression')
    require('DESKTOP_HEALTH_M26.md' in read('docs/README.md'), 'missing documentation link')
    print('M2.6 desktop health source contract: PASS (bounded, local, read-only)')
    print('  Source-only: actual Qt/Kirigami runtime NOT verified', flush=True)
    if args.build_dir:
        from verify_m17_suites import configured_contract
        _, desktop, sanitized = configured_contract(args.build_dir.resolve())
        names = ['knetsentry_health_client_contract', 'knetsentry_health_client_runtime']
        if desktop:
            names.append('knetsentry_qt_health_model')
            if not sanitized:
                names.append('knetsentry_gui_health_runtime')
        subprocess.run(['ctest', '--test-dir', str(args.build_dir.resolve()),
                        '--output-on-failure', '-R', '^(' + '|'.join(names) + ')$'],
                       check=True, timeout=100)
        print('M2.6 configured health tests: PASS; desktop=' + str(desktop))


if __name__ == '__main__':
    main()

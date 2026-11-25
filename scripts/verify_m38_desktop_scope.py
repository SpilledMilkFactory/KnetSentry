#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Read-only M3.8 source contract and optional configured desktop checks."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding='utf-8')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    header = read('apps/desktop/service_health_model.hpp')
    model = read('apps/desktop/service_health_model.cpp')
    page = read('apps/desktop/SectionPage.qml')
    window = read('apps/desktop/Main.qml')
    cpp = read('apps/desktop/main.cpp')
    tests = read('tests/qt/service_health_qtest.cpp')
    for name in ('scopeState', 'scopeNetworks', 'scopeInterfaces', 'scopeDenials'):
        require(f'Q_PROPERTY(QString {name} READ {name} NOTIFY changed FINAL)' in header,
                'missing read-only model property: ' + name)
        require(f'description: page.healthModel.{name}' in page, 'missing card binding: ' + name)
        require(f'"{name}"' in tests, 'missing read-only property test: ' + name)
    require('QML_UNCREATABLE' in header and 'WRITE ' not in header and 'Q_INVOKABLE' not in header,
            'health model must remain read-only')
    require('visible: page.sectionId === "settings"' in page and 'scopePanel.visible' in page,
            'scope UI must be restricted to Settings')
    require('currentPageScopeVisible' in window and 'currentPageScopeDenials' in window,
            'real QML scope cards must be observable')
    require('No operational approvals loaded' in model and 'No operational interface bindings' in model,
            'lifecycle-only scope is not an operational approval inventory')
    require('Policy revision and firewall state are not reported.' in model and
            'Network connection denials: unavailable (not collected).' in model and
            'Local IPC rejected requests: %1 (not network denials or incidents).' in model,
            'diagnostic and enforcement evidence must be distinguished')
    require('enum class ConfigurationMode : std::uint8_t { LifecycleOnly };' in
            read('include/knetsentry/service/configuration.hpp'), 'revisit scope presentation for new schema')
    require('NetworkAuthorization' not in read('apps/manager/main.cpp'),
            'revisit scope presentation once live policy publication is implemented')
    require('scope_page_matches(*root, false)' in cpp and
            'scope_page_matches(*root, true, true)' in cpp and
            'scope_page_matches(*root, true, false, true)' in cpp,
            'missing connected/disconnected/reconnected rendered scope assertions')
    require('!property.isWritable()' in tests and '!property.write(' in tests,
            'missing negative property write test')
    harness = read('scripts/check_m26_gui_runtime.py')
    require('KSIPC/1 ADMIN 0123456789abcdef' in harness and 'owner_file(config, VALID)' in harness and
            'M3.8 actual Settings scope and local IPC counter separation: PASS' in harness,
            'real rejection/configuration/restart harness missing')
    require('DESKTOP_NETWORK_SCOPE_M38.md' in read('docs/README.md'), 'missing documentation link')
    print('M3.8 read-only desktop scope source contract: PASS (actual Qt runtime not verified)', flush=True)
    if args.build_dir:
        from verify_m17_suites import configured_contract
        _, desktop, _ = configured_contract(args.build_dir.resolve())
        require(desktop, 'M3.8 runtime verification requires a desktop build')
        subprocess.run(['ctest', '--test-dir', str(args.build_dir.resolve()),
                        '-R', '^knetsentry_(qt_health_model|primary_navigation)$',
                        '--verbose', '--no-tests=error'], check=True, timeout=90)
        print('M3.8 configured read-only model and Settings navigation tests: PASS')


if __name__ == '__main__':
    main()

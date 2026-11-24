#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Check M2.9 registration and optionally execute real desktop controls."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    inventory = (ROOT / 'scripts/verify_m17_suites.py').read_text()
    for name in ('knetsentry_qt_daemon_control', 'knetsentry_gui_daemon_toolbar'):
        if f'NAME {name}' not in tests or f'"{name}"' not in inventory:
            raise ValueError('missing mandatory test: ' + name)
    source = (ROOT / 'apps/desktop/daemon_control.cpp').read_text()
    qml = (ROOT / 'apps/desktop/Main.qml').read_text()
    for token in ('!external_', 'geteuid() != 0', 'QProcess::Running', 'child_.terminate()',
                  'health_.available()', 'QTemporaryDir', 'setAutoRemove(false)'):
        if token not in source:
            raise ValueError('missing controller contract: ' + token)
    for token in ('header: Controls.ToolBar', 'toolbarTone', 'toolbarPulse', 'media-playback-start',
                  'media-playback-stop', 'daemonControl.startManager()', 'daemonControl.stopManager()'):
        if token not in qml:
            raise ValueError('missing toolbar binding: ' + token)
    if 'DESKTOP_DAEMON_TOOLBAR_M29.md' not in (ROOT / 'README.md').read_text():
        raise ValueError('missing documentation link')
    print('M2.9 toolbar source registration: PASS (runtime not verified)', flush=True)
    if args.build_dir:
        from verify_m17_suites import configured_contract
        _, desktop, sanitized = configured_contract(args.build_dir.resolve())
        if not desktop:
            raise ValueError('desktop build required for M2.9 runtime')
        regex = '^knetsentry_qt_daemon_control$' if sanitized else '^knetsentry_(qt_daemon_control|gui_daemon_toolbar)$'
        subprocess.run(['ctest', '--test-dir', str(args.build_dir.resolve()), '-R', regex,
                        '--verbose', '--no-tests=error'], check=True, timeout=90)
        print('M2.9 configured toolbar tests: PASS')


if __name__ == '__main__':
    main()

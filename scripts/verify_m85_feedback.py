#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Source registration and presentation boundaries; runtime checks are separate."""
from pathlib import Path
from verify_m17_suites import NONSAN_DESKTOP_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    main_qml = (ROOT / 'apps/desktop/Main.qml').read_text(encoding='utf-8')
    tokens = (ROOT / 'apps/desktop/DesignTokens.qml').read_text(encoding='utf-8')
    cpp = (ROOT / 'apps/desktop/main.cpp').read_text(encoding='utf-8')
    runtime = (ROOT / 'tests/dashboard_runtime_m81.py').read_text(encoding='utf-8')
    markers = ('property bool reduceMotion: true', 'Kirigami.Units.shortDuration',
               'platformMotionDuration <= 1', 'visibility !== Window.Minimized',
               'navigationMotion.stop()', 'navigationMotion.restart()',
               'running: window.motionAllowed && window.operationPending',
               'visible: window.operationPending', 'window.daemonControl.status',
               'window.toolbarPulse && window.motionAllowed',
               'dashboardModel.busy', 'eventModel.busy', 'alertModel.busy', 'timelineModel.busy',
               'width: 1920', 'height: 1080')
    if not all(marker in main_qml for marker in markers):
        raise ValueError('M8.5 motion/feedback binding missing')
    if main_qml.count('NumberAnimation {') != 2 or 'Behavior on' in main_qml:
        raise ValueError('M8.5 unexpected animation scope')
    if 'readonly property bool animateStatusChanges: false' not in tokens:
        raise ValueError('M8.5 security status animation prohibited')
    for marker in ('M8.5 motion opt-in, bounded navigation and immediate cancellation: PASS',
                   'M8.5 actual request feedback and completion: PASS'):
        if marker not in cpp:
            raise ValueError('M8.5 rendered assertion missing')
    if runtime.count('M8.5 actual request feedback and completion: PASS') != 2:
        raise ValueError('M8.5 authorized/denied coverage missing')
    if not {'knetsentry_visual_system', 'knetsentry_gui_dashboard_runtime'} <= NONSAN_DESKTOP_TESTS:
        raise ValueError('M8.5 mandatory test scope changed')
    if 'VISUAL_FEEDBACK_M85.md' not in (ROOT / 'docs/README.md').read_text(encoding='utf-8'):
        raise ValueError('M8.5 missing documentation index')
    print('M8.5 motion and visual feedback registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

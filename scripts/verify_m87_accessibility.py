#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Accessibility source registration; actual keyboard and visual checks are separate."""
from pathlib import Path
from verify_m17_suites import NONSAN_DESKTOP_TESTS

ROOT = Path(__file__).resolve().parent.parent


def require(ok, label):
    if not ok:
        raise ValueError('M8.7: ' + label)


def main():
    window = (ROOT / 'apps/desktop/Main.qml').read_text()
    page = (ROOT / 'apps/desktop/SectionPage.qml').read_text()
    cpp = (ROOT / 'apps/desktop/main.cpp').read_text()
    tokens = (ROOT / 'apps/desktop/DesignTokens.qml').read_text()
    for marker in ('sequence: "F6"', 'sequence: "Shift+F6"',
                   'const nextPage = sectionPageComponent.createObject(null, { "sectionId": sectionId }) as SectionPage',
                   'nextPage.focusPrimary()', 'onActiveFocusItemChanged:',
                   'property int textScalePercent: 100', 'percent === 100 || percent === 125 || percent === 150',
                   'window.applyTextScale(percent)', 'property bool reduceMotion: true',
                   'width: 1920', 'height: 1080'):
        require(marker in window, marker)
    for marker in ('Keys.onReturnPressed: inspectCurrent()', 'Keys.onEnterPressed: inspectCurrent()',
                   'Keys.onSpacePressed: inspectCurrent()', 'Keys.onUpPressed: decrementCurrentIndex()',
                   'Keys.onDownPressed: incrementCurrentIndex()', 'keyNavigationWraps: false',
                   'Accessible.role: Accessible.List', 'activeFocusOnTab: enabled'):
        require(page.count(marker) == 3, 'all three lists: ' + marker)
    for marker in ('revealKeyboardFocus(item: Item)', 'item.mapToItem(scroller.contentItem',
                   'qsTr("Application text size")', 'page.compactLayout ? 1 :',
                   'font.pixelSize: Math.round(14 * textScale)'):
        require(marker in page, marker)
    require('animateStatusChanges: false' in tokens, 'security state must not animate')
    require('QCoreApplication::sendEvent(&window, &press)' in cpp, 'real Qt key dispatch missing')
    require('QFontInfo(app.font()).pixelSize()' in cpp, 'platform font baseline missing')
    cases = {'event': 'event_explorer_runtime_m68.py', 'alert': 'alert_interface_runtime_m77.py',
             'timeline': 'investigation_runtime_m84.py'}
    for kind, name in cases.items():
        marker = f'M8.7 {kind} keyboard inspection: PASS'
        require(marker in cpp and marker in (ROOT / 'tests' / name).read_text(), kind + ' runtime gate')
    require('M8.7 rendered text scale and focus targets: PASS' in cpp, 'scale runtime gate')
    require({'knetsentry_visual_system', 'knetsentry_gui_event_explorer_runtime',
             'knetsentry_gui_alert_interface_runtime', 'knetsentry_gui_investigation_runtime'} <= NONSAN_DESKTOP_TESTS,
            'mandatory non-sanitized desktop suite changed')
    require('ACCESSIBILITY_M87.md' in (ROOT / 'docs/README.md').read_text(), 'documentation index')
    print('M8.7 keyboard accessibility registration: PASS (runtime and manual review separate)')


if __name__ == '__main__':
    main()

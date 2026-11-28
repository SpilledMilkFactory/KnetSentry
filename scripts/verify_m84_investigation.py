#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Investigation registration; runtime qualification remains separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS, NONSAN_DESKTOP_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'apps/desktop/CMakeLists.txt': ('timeline_model.cpp', 'timeline_model.hpp'),
        'apps/desktop/Main.qml': ('required property TimelineModel timelineModel', 'timelineModel: window.timelineModel', 'window.timelineModel.clear()'),
        'apps/desktop/SectionPage.qml': ('page.timelineModel.refresh()', 'page.timelineModel.follow(', 'page.timelineModel.verifyEvidence(', 'Text.PlainText'),
        'apps/desktop/main.cpp': ('self-test-timeline', 'M8.4 rendered timeline and evidence lifecycle: PASS'),
        'apps/desktop/timeline_model.cpp': ('AlertQuery::Operation::Evidence', 'expiry_.setInterval(30000)', 'result.evidence'),
        'tests/CMakeLists.txt': ('NAME knetsentry_investigation_timeline_contract', 'NAME knetsentry_gui_investigation_runtime'),
        'docs/README.md': ('INVESTIGATION_TIMELINE_M84.md',),
    }
    for path, markers in checks.items():
        if not all(marker in (ROOT / path).read_text(encoding='utf-8') for marker in markers):
            raise ValueError('M8.4 missing registration: ' + path)
    if 'knetsentry_investigation_timeline_contract' not in CORE_TESTS or 'knetsentry_gui_investigation_runtime' not in NONSAN_DESKTOP_TESTS:
        raise ValueError('M8.4 missing suite registration')
    if 'Operation::Acknowledge' in (ROOT / 'apps/desktop/timeline_model.cpp').read_text():
        raise ValueError('Timeline must not expose mutation')
    print('M8.4 investigation registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

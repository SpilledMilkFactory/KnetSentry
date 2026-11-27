#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M7.7 registration; runtime qualification remains separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS, NONSAN_DESKTOP_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'src/service/local_ipc.cpp': ('SO_PEERCRED', 'alert_writable_', 'audit.persistent()', 'AlertAcknowledgeAuthorized', 'AlertAcknowledged'),
        'src/service/alert_query.cpp': ('read_alerts(', 'update_alert(', 'store.raw(', 'store.normalized(', 'max_alert_response'),
        'src/service/health_client.cpp': ('decode_alert_page', 'begin_alerts'),
        'apps/manager/main.cpp': ('--alert-dir', 'load_alert_profile', '--alert-access'),
        'apps/desktop/alert_model.hpp': ('QAbstractListModel', 'QML_UNCREATABLE'),
        'apps/desktop/SectionPage.qml': ('alertModel.acknowledge()', 'alertModel.inspectEvidence(', 'Text.PlainText'),
        'docs/README.md': ('ALERT_INTERFACE_M77.md',),
        'scripts/verify_m12_hardening.py': ('alert_interface_m77.cpp', 'alert_model.cpp', 'knetsentry_alert_interface_test'),
    }
    for path, markers in checks.items():
        text = (ROOT / path).read_text()
        for marker in markers:
            if marker not in text:
                raise ValueError(f'M7.7 missing {marker}: {path}')
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    for name in ('knetsentry_alert_interface_contract', 'knetsentry_alert_interface_runtime', 'knetsentry_gui_alert_interface_runtime'):
        if name not in CORE_TESTS | NONSAN_DESKTOP_TESTS or f'NAME {name}' not in tests:
            raise ValueError('missing test: ' + name)
    print('M7.7 alert interface registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

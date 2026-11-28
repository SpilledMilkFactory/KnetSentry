#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Workspace source registration; actual storage and desktop runtime tested separately."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS, NONSAN_DESKTOP_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    checks = {
        'apps/desktop/CMakeLists.txt': ('workspace_model.cpp', 'workspace_model.hpp'),
        'apps/desktop/Main.qml': ('required property WorkspaceModel workspaceModel', 'workspaceModel: window.workspaceModel', 'width: 1920', 'height: 1080', 'visible: true'),
        'apps/desktop/SectionPage.qml': ('workspaceGrid.columns', 'workspaceModel.save()', 'workspaceModel.configure'),
        'apps/desktop/main.cpp': ('self-test-workspace', 'workspace rendered preferences: PASS', 'QWindow::Windowed', 'default windowed geometry: PASS'),
        'include/knetsentry/desktop/workspace_preferences.hpp': ('O_NOFOLLOW', 'O_EXCL', 'AT_SYMLINK_NOFOLLOW', '::renameat', '::fsync'),
        'tests/CMakeLists.txt': ('NAME knetsentry_workspace_preferences_contract', 'NAME knetsentry_gui_workspace_runtime'),
        'docs/README.md': ('WORKSPACE_M83.md',),
    }
    for path, markers in checks.items():
        if not all(marker in (ROOT / path).read_text(encoding='utf-8') for marker in markers):
            raise ValueError('M8.3 missing registration: ' + path)
    if 'knetsentry_workspace_preferences_contract' not in CORE_TESTS or 'knetsentry_gui_workspace_runtime' not in NONSAN_DESKTOP_TESTS:
        raise ValueError('M8.3 missing suite registration')
    print('M8.3 workspace registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

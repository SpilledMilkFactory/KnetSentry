#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.4 warning follow-up structure; real Qt runtime is a separate test."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing {rel}")
        return ""
    return path.read_text(encoding="utf-8")

main = read("apps/desktop/Main.qml")
cpp = read("apps/desktop/main.cpp")
tests = read("tests/CMakeLists.txt")
runtime = read("scripts/check_m14_runtime_diagnostics.py")
helper = read("scripts/manage_dev_desktop_entry.py")
guide = read("docs/development/GUI_NAVIGATION.md")
for path, content in (("scripts/check_m14_runtime_diagnostics.py", runtime),
                      ("scripts/manage_dev_desktop_entry.py", helper)):
    require("SPDX\x2dLicense-Identifier: MIT" in content[:180], f"{path}: missing SPDX")
require('sectionPageComponent.createObject(null, { "sectionId": sectionId })' in main,
        "SectionPage must be explicitly instantiated with a required section identifier")
require('pageStack.replace(nextPage)' in main and 'nextPage.destroy()' in main,
        "page must be handed to PageRow or destroyed on failed adoption")
require('pageStack.replace(sectionPageComponent,' not in main,
        "direct Component replacement reintroduces upstream Kirigami warning")
require('for (int pass = 0; pass < 4; ++pass)' in cpp,
        "navigation test must repeat seven routes four times")
require('knetsentry_navigation_qml_diagnostics' in tests and
        'check_m14_runtime_diagnostics.py' in tests and
        'if(NOT KNETSENTRY_ENABLE_SANITIZERS)' in tests,
        "real stderr regression must be desktop-only, non-instrumented")
require('Created graphical object was not placed in the graphics scene.' in runtime,
        "runtime test must reject the actual observed QML warning")
require('QT_QPA_PLATFORM' in runtime and '--self-test-navigation' in runtime,
        "runtime test must execute the actual offscreen Kirigami application")
require('LSAN_OPTIONS' not in runtime and 'QT_LOGGING_RULES' not in runtime,
        "runtime test must not disable or suppress leak/QML diagnostics")
require('APP_ID = "io.github.spilledmilkfactory.KnetSentry"' in helper and
        'X-KnetSentry-Dev-Managed=true' in helper,
        "desktop entry helper must match exact app identity and carry ownership marker")
require('group.add_argument("--install"' in helper and 'args.uninstall' in helper and 'args.check' in helper,
        "developer desktop entry management must be opt-in and reversible")
require('refusing to overwrite existing non-development desktop entry' in helper,
        "developer entry helper must not overwrite unrelated installed entries")
require('if os.geteuid() == 0' in helper,
        "developer entry helper must refuse elevated execution")
require('DrawerHandle' in guide and 'upstream' in guide and
        'does not modify, vendor, or suppress' in guide,
        "do not claim the external Kirigami binding loop was repaired")
require('python3 scripts/manage_dev_desktop_entry.py --uninstall' in guide,
        "document how to undo optional per-user portal registration")
require('CC-BY-SA-4.0' in guide[:140], "guide must retain documentation licensing")
if errors:
    print('M1.4 warning follow-up verification: FAIL', file=sys.stderr)
    for error in errors:
        print(f'  - {error}', file=sys.stderr)
    sys.exit(1)
print('M1.4 warning follow-up verification: PASS')
print('  Explicit Kirigami page adoption and failure cleanup; 28-navigation runtime diagnostic')
print('  Per-user desktop registration is optional; upstream DrawerHandle issue remains separate')
print('  Source-only check: Ubuntu Qt/Kirigami warning resolution NOT verified here')

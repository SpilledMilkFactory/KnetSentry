#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.4 navigation contract (source) and optional real Qt/Kirigami runtime.

Source checks are not a replacement for actual Ubuntu desktop CTest and GUI
acceptance. Pass --build-dir to run the actual seven-section routing check.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECTIONS = ("dashboard", "assets", "events", "detections", "alerts",
            "investigations", "settings")
ERRORS: list[str] = []


def require(ok: bool, why: str) -> None:
    if not ok:
        ERRORS.append(why)


def read(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        ERRORS.append(f"missing {rel}")
        return ""
    return p.read_text(encoding="utf-8")


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build-dir", type=Path,
                    help="Execute the built GUI with the real seven-section QML test")
args = parser.parse_args()

main = read("apps/desktop/Main.qml")
page = read("apps/desktop/SectionPage.qml")
cpp = read("apps/desktop/main.cpp")
cmake = read("apps/desktop/CMakeLists.txt")
tests = read("tests/CMakeLists.txt")
policy = read("scripts/verify_m13_lsan.py")
guide = read("docs/development/GUI_NAVIGATION.md")
readme = read("README.md")

for name, content in (("Main.qml", main), ("SectionPage.qml", page)):
    require(content.startswith("// SPDX-FileCopyrightText: 2026 Chris Sutton\n"
                               "// SPDX\x2dLicense-Identifier: MIT"),
            f"{name}: expected MIT SPDX header")
require("QML_FILES Main.qml SectionPage.qml" in cmake, "both QML pages must be embedded")
require("Kirigami.ApplicationWindow" in main and "Kirigami.GlobalDrawer" in main,
        "expected Kirigami window/drawer")
require('pageStack.initialPage: SectionPage { sectionId: "dashboard" }' in main,
        "initial dashboard must be an actual SectionPage")
require('sectionPageComponent.createObject(null, { "sectionId": sectionId })' in main,
        "navigation must instantiate the section page before PageRow adoption")
require('pageStack.replace(nextPage)' in main and 'nextPage.destroy()' in main,
        "top-level navigation must replace with the pre-created page and clean up failures")
require('pageStack.replace(sectionPageComponent,' not in main,
        "do not reintroduce upstream PageRow Component-instantiation diagnostics")
require("pageStack.push(" not in main, "top-level navigation must not accumulate pages")
require("isValidSection(sectionId)" in main and "onNavigationRequestChanged" in main,
        "navigation authorization/verification entry point missing")
require("readonly property int navigationDepth: pageStack.depth" in main,
        "depth must be observable in the runtime test")
require("readonly property string currentPageSection: pageStack.currentItem" in main,
        "actual displayed page must be observable in the runtime test")
require("monitoring is not active" in main.lower(),
        "persistent inactive-monitoring notice missing")

routes = re.findall(r'onTriggered:\s*window\.navigateTo\("([^"]+)"\)', main)
require(tuple(routes) == SECTIONS, f"expected seven ordered drawer routes, found {routes}")
shortcuts = re.findall(r'shortcut:\s*"(Ctrl\+\d)"', main)
require(shortcuts == [f"Ctrl+{i}" for i in range(1, 8)],
        "expected unique Ctrl+1 .. Ctrl+7 section shortcuts")
for ident in SECTIONS:
    require(f'case "{ident}":' in main and f'case "{ident}":' in page,
            f"missing distinct title/content for {ident}")
require("Kirigami.Page" in page and 'objectName: "knetSentrySectionPage"' in page,
        "missing actual standalone section page")
require("Not operational" in page and "No devices, alerts, detections, or incidents are simulated." in page,
        "all destinations must clearly state they are placeholders")
require("required property string sectionId" in page,
        "invalid/missing section identifiers must not silently be accepted")
require('for (int pass = 0; pass < 4; ++pass)' in cpp,
        "runtime navigation must cover repeated page replacement")
require("--self-test-navigation" not in main and "self-test-navigation" in cpp,
        "navigation runtime test must be a C++ CLI option, not a QML shell command")
for token in ("navigationRequest", "currentPageSection", "navigationDepth",
              'QStringLiteral("unapproved")', "QCoreApplication::processEvents()",
              "primary navigation: PASS (7 sections; no telemetry)"):
    require(token in cpp, f"missing negative/integration runtime test: {token}")
require('knetsentry_primary_navigation' in tests and '--self-test-navigation' in tests,
        "navigation CTest must invoke the actual binary")
require('QT_QPA_PLATFORM=offscreen' in tests and 'QT_QUICK_BACKEND=software' in tests,
        "navigation CTest must run without a physical desktop")
require('set_property(TEST knetsentry_primary_navigation APPEND PROPERTY ENVIRONMENT' in tests,
        "sanitizer LSan scope must include the new QML-only test")
require('tests.count("LSAN_OPTIONS=suppressions=") == 3' in policy,
        "existing negative-control policy must remain scoped to only two QML tests and probe")
require("CC-BY-SA-4.0" in guide[:140], "navigation guide must have docs license")
require("GUI_NAVIGATION.md" in readme, "README needs new navigation guide link")

if args.build_dir:
    path = (ROOT / args.build_dir).resolve()
    binary = path / "apps/desktop/knetsentry"
    require(binary.is_file(), f"no real Qt desktop executable: {binary}")
    if binary.is_file():
        env = os.environ.copy()
        env.update({"QT_QPA_PLATFORM": "offscreen", "QT_QUICK_BACKEND": "software",
                    "QT_QUICK_CONTROLS_STYLE": "Basic"})
        try:
            result = subprocess.run([str(binary), "--self-test-navigation"], env=env,
                                    cwd=ROOT, capture_output=True, text=True, timeout=30)
            require(result.returncode == 0 and
                    "M1.4 primary navigation: PASS (7 sections; no telemetry)" in result.stdout,
                    f"real Kirigami navigation failed: exit={result.returncode}\n"
                    f"stdout={result.stdout}\nstderr={result.stderr}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            ERRORS.append(f"unable to execute Qt/Kirigami navigation test: {exc}")

if ERRORS:
    print("M1.4 navigation verification: FAIL", file=sys.stderr)
    for error in ERRORS:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)
print("M1.4 navigation verification: PASS")
print("  7 distinct Kirigami drawer routes and pages; bounded replacement; invalid route rejection")
print("  Existing QML LSan scope and first-party deliberate-leak negative control retained")
if args.build_dir:
    print("  Verified actual Qt/Kirigami navigation runtime:", args.build_dir)
else:
    print("  Source-only checks: Ubuntu Qt/Kirigami navigation runtime NOT verified")

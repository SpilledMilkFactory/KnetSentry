#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.5 visual design contract: structural, WCAG contrast, optional Qt runtime.

Without --build-dir, this performs policy/source checks only, NOT GUI tests.
Full Ubuntu Qt/Kirigami Release/Debug/Clazy/ASan acceptance remains separate.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ISSUES: list[str] = []


def need(test: bool, reason: str) -> None:
    if not test:
        ISSUES.append(reason)


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        ISSUES.append(f"missing {rel}")
        return ""
    return path.read_text(encoding="utf-8")


def luminance(hex_color: str) -> float:
    match = re.fullmatch(r"#[0-9a-fA-F]{6}", hex_color)
    if not match:
        raise ValueError(f"invalid color: {hex_color}")
    rgb = [int(hex_color[i:i+2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
              for c in rgb]
    return sum(x * y for x, y in zip(linear, (0.2126, 0.7152, 0.0722)))


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build-dir", type=Path,
                    help="Also execute the actual Qt/Kirigami visual startup test")
args = parser.parse_args()

names = ("Main.qml", "SectionPage.qml", "DesignTokens.qml", "SurfaceCard.qml",
         "StatusBadge.qml", "SeverityBadge.qml")
qml = {name: read("apps/desktop/" + name) for name in names}
for name, content in qml.items():
    need(content.startswith("// SPDX-FileCopyrightText: 2026 Chris Sutton\n"
                            "// SPDX-License-Identifier: MIT\n"),
         f"{name}: missing first-party MIT SPDX")
cmake = read("apps/desktop/CMakeLists.txt")
for name in names:
    need(name in cmake, f"Qt module doesn't embed {name}")
need("QML_FILES Main.qml SectionPage.qml" in cmake,
     "M1.4 Qt QML module registration changed")
need("Kirigami.ApplicationWindow" in qml["Main.qml"] and
     "Kirigami.GlobalDrawer" in qml["Main.qml"],
     "the established Kirigami shell/drawer is missing")
need("sectionPageComponent.createObject(null" in qml["Main.qml"] and
     "pageStack.replace(nextPage)" in qml["Main.qml"],
     "reintroduced faulty pre-M1.4 page creation")
need("readonly property bool compactLayout" in qml["SectionPage.qml"] and
     "Flow {" in qml["SectionPage.qml"] and
     "Flickable {" in qml["SectionPage.qml"],
     "responsive flow and scrolling foundation missing")
need("Kirigami.Theme.backgroundColor" in qml["SurfaceCard.qml"] and
     "Kirigami.Theme.textColor" in qml["SurfaceCard.qml"],
     "reusable cards must follow the active platform palette")
need("Kirigami.Theme.textColor" in qml["SectionPage.qml"],
     "page text must follow the active platform palette")
need("Accessible.name" in qml["StatusBadge.qml"] and
     "Accessible.name" in qml["SeverityBadge.qml"],
     "badges must have a textual accessibility name")
need("Severity is distinct from monitoring availability" in qml["SectionPage.qml"],
     "severity examples must be distinguished from monitoring health")
need("No devices, alerts, detections, or incidents are simulated." in qml["SectionPage.qml"] and
     "Not operational" in qml["SectionPage.qml"],
     "non-operational information must remain explicit")
need("readonly property bool animateStatusChanges: false" in qml["DesignTokens.qml"],
     "animated severity/status changes must remain disabled")

# Qt QML value types are module-scoped: `color` comes from QtQuick, not
# QtQml. The original M1.5 source passed the static contrast checks but
# failed to instantiate DesignTokens.qml in *every* desktop configuration.
# Catch that exact regression even when this verifier runs without Qt.
need(bool(re.search(r"^import[ \t]+QtQuick(?:[ \t]|$)",
                    qml["DesignTokens.qml"], re.MULTILINE)),
     "DesignTokens.qml: typed 'color' properties require an import QtQuick")
need(len(re.findall(r"^\s*readonly property color\s+\w+\s*:",
                    qml["DesignTokens.qml"], re.MULTILINE)) == 6,
     "DesignTokens.qml: six semantic color properties must stay strongly typed")

tokens = qml["DesignTokens.qml"]
hexes = dict(re.findall(r'readonly property color\s+(\w+):\s*"(#[0-9A-Fa-f]{6})"', tokens))
expected = ("criticalBackground", "highBackground", "mediumBackground",
            "lowBackground", "unknownBackground", "severityForeground")
need(set(expected) <= set(hexes), "missing semantic severity colors")
need(len({hexes.get(x) for x in expected[:-1]}) == 5,
     "severity categories must have distinct samples")
if set(expected) <= set(hexes):
    for key in expected[:-1]:
        score = contrast(hexes[key], hexes["severityForeground"])
        need(score >= 4.5, f"{key} contrast {score:.2f}:1 is under WCAG 4.5:1")
need('switch (level)' in qml["SeverityBadge.qml"] and
     'case "critical"' in qml["SeverityBadge.qml"] and
     'case "unknown"' in qml["SeverityBadge.qml"],
     "severity badge must show textual category, including unknown")
need('property string label: qsTr("Not operational")' in qml["StatusBadge.qml"],
     "monitoring-availability badge default must be non-operational")

cpp = read("apps/desktop/main.cpp")
tests = read("tests/CMakeLists.txt")
need("self-test-visual" in cpp and
     "M1.5 visual system: PASS (platform palette; no telemetry)" in cpp and
     "visualTokensValid" in cpp and "currentPageVisualSystem" in cpp,
     "missing real QML design system integration test")
need("knetsentry_visual_system" in tests and "--self-test-visual" in tests and
     "if(NOT KNETSENTRY_ENABLE_SANITIZERS)" in tests,
     "visual system runtime test must be desktop/non-sanitized only")
need('QT_QPA_PLATFORM=offscreen' in tests and 'QT_QUICK_BACKEND=software' in tests,
     "Qt runtime must support displayless test execution")
need("tests.count(\"LSAN_OPTIONS=suppressions=\") == 3" in
     read("scripts/verify_m13_lsan.py"),
     "M1.3 scoped sanitizer negative-control contract changed")

guide = read("docs/development/VISUAL_DESIGN_SYSTEM.md")
need("SPDX-License-Identifier: CC-BY-SA-4.0" in guide[:180],
     "visual guide must use approved documentation license")
for phrase in ("light", "dark", "spacing", "accessibility", "contrast",
               "reduced motion", "severity", "monitoring availability", "GNOME", "Plasma"):
    need(phrase.lower() in guide.lower(), f"missing visual design policy: {phrase}")
need("VISUAL_DESIGN_SYSTEM.md" in read("README.md"),
     "README must link to visual design system guidance")

if args.build_dir:
    binary = (ROOT / args.build_dir / "apps/desktop/knetsentry").resolve()
    need(binary.is_file(), f"missing real Qt/Kirigami executable: {binary}")
    if binary.is_file():
        env = os.environ.copy()
        env.update(QT_QPA_PLATFORM="offscreen", QT_QUICK_BACKEND="software",
                   QT_QUICK_CONTROLS_STYLE="Basic")
        try:
            result = subprocess.run([str(binary), "--self-test-visual"],
                                    cwd=ROOT, env=env, capture_output=True, text=True,
                                    timeout=30, check=False)
            need(result.returncode == 0 and
                 "M1.5 visual system: PASS (platform palette; no telemetry)" in result.stdout,
                 f"Qt/Kirigami visual test failed: exit={result.returncode}\n"
                 f"stdout={result.stdout}\nstderr={result.stderr}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            ISSUES.append(f"unable to execute visual QML test: {exc}")

if ISSUES:
    print("M1.5 visual design verification: FAIL", file=sys.stderr)
    for issue in ISSUES:
        print(f"  - {issue}", file=sys.stderr)
    sys.exit(1)
print("M1.5 visual design verification: PASS")
print("  6 QML components, platform-driven light/dark palette, semantic status/severity")
print("  5 severity pairs checked at >=4.5:1; responsive flow and accessibility labels")
if args.build_dir:
    print(f"  Verified actual Qt/Kirigami design-system runtime: {args.build_dir}")
else:
    print("  Source-only checks: real Ubuntu 26.04 QML runtime NOT verified")

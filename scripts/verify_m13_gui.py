#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.3 Qt/Kirigami source and optional real QML runtime verification.

Source checks do NOT qualify the GUI. Pass --build-dir and run CTest on Ubuntu
for an actual import/instantiation check with the installed Kirigami runtime.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors: list[str] = []


def require(ok: bool, reason: str) -> None:
    if not ok:
        errors.append(reason)


def source(name: str) -> str:
    file = ROOT / name
    if not file.is_file():
        errors.append(f"missing file: {name}")
        return ""
    return file.read_text(encoding="utf-8")


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build-dir", type=Path, help="Require real executable and test QML imports")
args = parser.parse_args()

root = source("CMakeLists.txt")
cmake = source("apps/desktop/CMakeLists.txt")
main = source("apps/desktop/main.cpp")
qml = source("apps/desktop/Main.qml")
tests = source("tests/CMakeLists.txt")
foundation = source("docs/development/GUI_FOUNDATION.md")
desktop = source("packaging/desktop/io.github.spilledmilkfactory.KnetSentry.desktop")

for name in ("apps/desktop/main.cpp", "apps/desktop/Main.qml"):
    require("SPDX-License-Identifier: MIT" in source(name)[:120], f"{name}: MIT SPDX missing")
for name in ("CMakeLists.txt", "apps/desktop/CMakeLists.txt", "tests/CMakeLists.txt"):
    require("SPDX-License-Identifier: BSD-2-Clause" in source(name)[:140], f"{name}: BSD SPDX missing")
require("SPDX-License-Identifier: MIT" in desktop[:120], "desktop metadata license missing")
require("CC-BY-SA-4.0" in foundation[:130], "GUI guide license missing")

for token in ("find_package(Qt6", "find_package(KF6", "qt_standard_project_setup(REQUIRES 6.5)"):
    require(token in root, f"root CMake missing {token}")
require("ecm_find_qmlmodule(org.kde.kirigami REQUIRED)" not in root,
        "legacy qmlplugindump discovery still used; rely on mandatory actual import test")
require(root.index("if(KNETSENTRY_BUILD_DESKTOP)") < root.index("qt_standard_project_setup"),
        "Qt setup not guarded by desktop option")
for token in ("qt_add_qml_module(knetsentry", "URI io.github.spilledmilkfactory.KnetSentry",
              "QML_FILES Main.qml", "Qt6::Qml", "Qt6::Quick", "Qt6::QuickControls2",
              "KnetSentry::Core", "knetsentry_apply_project_options(knetsentry)"):
    require(token in cmake, f"desktop CMake missing {token}")
for token in ("#include <QCoreApplication>", "#include <QGuiApplication>",
              "#include <QQmlApplicationEngine>", "QQmlApplicationEngine engine",
              'engine.loadFromModule("io.github.spilledmilkfactory.KnetSentry", "Main")',
              "engine.rootObjects().size() != 1", "qobject_cast<QQuickWindow *>",
              'QStringLiteral("knetSentryMainWindow")', "--help", "--version",
              "self-test-qml", "QCoreApplication app(argc, argv)", "QGuiApplication app(argc, argv)"):
    require(token in main, f"C++ desktop bootstrap missing {token}")
for token in ("import QtQuick", "import org.kde.kirigami as Kirigami",
              "Kirigami.ApplicationWindow", 'objectName: "knetSentryMainWindow"',
              "visible: true", "monitoring is not active", "pageStack.initialPage"):
    require(token.lower() in qml.lower(), f"QML window missing {token}")
for token in ("knetsentry_kirigami_qml_startup", "--self-test-qml",
              "QT_QPA_PLATFORM=offscreen", "QT_QUICK_BACKEND=software", "TIMEOUT 30"):
    require(token in tests, f"mandatory headless startup test missing {token}")
require("KNETSENTRY_BUILD_DESKTOP" in tests and "if(KNETSENTRY_BUILD_DESKTOP)" in tests,
        "desktop-only tests not gated correctly")
require("Terminal=false" in desktop and "Exec=knetsentry" in desktop,
        "desktop entry has incorrect launch metadata")
require("GUI_FOUNDATION.md" in source("README.md"), "README missing M1.3 documentation link")
require("Qt6::" not in source("src/core/CMakeLists.txt"), "Qt dependency leaked into core")

if args.build_dir:
    path = (ROOT / args.build_dir).resolve()
    binary = path / "apps/desktop/knetsentry"
    require(binary.is_file(), f"missing built desktop executable: {binary}")
    if binary.is_file():
        environment = os.environ.copy()
        environment.update({"QT_QPA_PLATFORM": "offscreen",
                            "QT_QUICK_BACKEND": "software",
                            "QT_QUICK_CONTROLS_STYLE": "Basic"})
        try:
            run = subprocess.run([str(binary), "--self-test-qml"], cwd=ROOT,
                                 env=environment, text=True, capture_output=True, timeout=30)
            require(run.returncode == 0 and "Kirigami QML smoke: PASS" in run.stdout,
                    f"actual QML load failed: exit={run.returncode}\n{run.stdout}\n{run.stderr}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"unable to execute Qt/Kirigami runtime test: {exc}")

if errors:
    print("M1.3 GUI foundation verification: FAIL", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    sys.exit(1)

print("M1.3 GUI foundation verification: PASS")
print("  Qt QML module and Kirigami.ApplicationWindow, headless runtime test registered")
if args.build_dir:
    print("  Verified real Qt/Kirigami QML instantiation:", args.build_dir)
else:
    print("  Source-only checks: actual Qt/Kirigami startup NOT verified")

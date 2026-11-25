#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.3 Qt/Kirigami source and optional real QML runtime verification.

Source checks do NOT qualify the GUI. Pass --build-dir and run CTest on Ubuntu
for an actual import/instantiation check with the installed Kirigami runtime.
"""
from __future__ import annotations

import argparse
import json
import shlex
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
parser.add_argument("--compile-commands", type=Path,
                    help="Check that the GCC warning exception is present only in the Qt-generated cache loader")
args = parser.parse_args()

root = source("CMakeLists.txt")
cmake = source("apps/desktop/CMakeLists.txt")
main = source("apps/desktop/main.cpp")
qml = source("apps/desktop/Main.qml")
tests = source("tests/CMakeLists.txt")
foundation = source("docs/development/GUI_FOUNDATION.md")
desktop = source("packaging/desktop/io.github.spilledmilkfactory.KnetSentry.desktop")

for name in ("apps/desktop/main.cpp", "apps/desktop/Main.qml"):
    require("SPDX\x2dLicense-Identifier: MIT" in source(name)[:120], f"{name}: MIT SPDX missing")
for name in ("CMakeLists.txt", "apps/desktop/CMakeLists.txt", "tests/CMakeLists.txt"):
    require("SPDX\x2dLicense-Identifier: BSD-2-Clause" in source(name)[:140], f"{name}: BSD SPDX missing")
require("SPDX\x2dLicense-Identifier: MIT" in desktop[:120], "desktop metadata license missing")
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
require("GUI_FOUNDATION.md" in source("docs/README.md"), "Documentation index missing M1.3 documentation link")
require("Qt6::" not in source("src/core/CMakeLists.txt"), "Qt dependency leaked into core")

# M1.3 follow-up: Qt-generated cache registration can trip a GCC 15 diagnostic
# in Qt headers. Keep project warnings-as-errors intact and allow a narrowly
# scoped, visible *warning* only for that single generated translation unit.
for token in (
    'if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")',
    '${CMAKE_CURRENT_BINARY_DIR}/.rcc/qmlcache/knetsentry_qmlcache_loader.cpp',
    'set_source_files_properties("${_knetsentry_qmlcache_loader}"',
    'COMPILE_OPTIONS "-Wno-error=null-dereference"',
):
    require(token in cmake, f"Qt-generated loader warning boundary missing: {token}")
require("NO_CACHEGEN" not in cmake and "QT_QML_NO_CACHEGEN" not in cmake,
        "QML cache generation must remain enabled")
require("-Wno-error=null-dereference" not in source("cmake/KnetSentryBuildOptions.cmake"),
        "exception leaked into project-wide compiler options")

if args.compile_commands:
    path = args.compile_commands.resolve()
    if not path.is_file():
        errors.append(f"missing compilation database: {path}")
    else:
        try:
            commands = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            commands = []
            errors.append(f"cannot read compilation database: {exc}")
        compiler_records = list((path.parent / "CMakeFiles").glob("*/CMakeCXXCompiler.cmake"))
        require(len(compiler_records) == 1,
                f"expected one configured C++ compiler identity, found {len(compiler_records)}")
        compiler_id = ""
        if len(compiler_records) == 1:
            details = compiler_records[0].read_text(encoding="utf-8")
            match = re.search(r'set\(CMAKE_CXX_COMPILER_ID "([^"]+)"\)', details)
            if match:
                compiler_id = match.group(1)
        require(compiler_id in ("GNU", "Clang"),
                f"unknown or unsupported compiler identity: {compiler_id or '(missing)'}")
        loader = []
        for entry in commands:
            file = Path(entry.get("file", ""))
            if "arguments" in entry:
                arguments = entry["arguments"]
            else:
                arguments = shlex.split(entry.get("command", ""))
            if file.name == "knetsentry_qmlcache_loader.cpp":
                loader.append(entry)
                for token in ("-Werror", "-Wnull-dereference"):
                    require(token in arguments, f"generated loader missing {token}")
                require(("-Wno-error=null-dereference" in arguments) == (compiler_id == "GNU"),
                        f"generated loader has incorrect GCC-only exception ({compiler_id})")
            else:
                require("-Wno-error=null-dereference" not in arguments,
                        f"per-source warning exception unexpectedly applies to {file.name}")
        require(len(loader) == 1,
                f"expected exactly one generated Qt QML cache loader command, found {len(loader)}")


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
if args.compile_commands:
    print("  Scoped Qt-generated loader warning exception verified:", args.compile_commands)
if args.build_dir:
    print("  Verified real Qt/Kirigami QML instantiation:", args.build_dir)
else:
    print("  Source-only checks: actual Qt/Kirigami startup NOT verified")

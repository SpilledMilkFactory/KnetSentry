#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.1 offline structure/contract checks; does not claim full Qt build success."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors: list[str] = []

def check(ok: bool, msg: str) -> None:
    if not ok:
        errors.append(msg)

def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        errors.append(f"missing file: {relative}")
        return ""
    return path.read_text(encoding="utf-8")

cmake_paths = ("CMakeLists.txt", "src/core/CMakeLists.txt",
               "apps/desktop/CMakeLists.txt", "tests/CMakeLists.txt")
for rel in cmake_paths:
    check(read(rel).startswith("# SPDX-FileCopyrightText: 2026 Chris Sutton\n"
                                    "# SPDX\x2dLicense-Identifier: BSD-2-Clause"),
          f"{rel}: missing BSD-2-Clause header")
check("BSD 2-Clause License" in read("LICENSES/BSD-2-Clause.txt"),
      "BSD-2-Clause license text missing")
cpp_paths = ("include/knetsentry/core/build_info.hpp",
             "src/core/build_info.cpp", "apps/desktop/main.cpp",
             "tests/core_smoke.cpp")
for rel in cpp_paths:
    check(read(rel).startswith("// SPDX-FileCopyrightText: 2026 Chris Sutton\n"
                                    "// SPDX\x2dLicense-Identifier: MIT"),
          f"{rel}: missing MIT header")
root = read("CMakeLists.txt")
for token in ("LANGUAGES CXX", "CMAKE_CXX_STANDARD 23",
              "KNETSENTRY_BUILD_DESKTOP", "add_subdirectory(src/core)",
              "find_package(ECM", "find_package(Qt6", "find_package(KF6",
              "qt_standard_project_setup(REQUIRES 6.5)",
              "add_subdirectory(tests)"):
    check(token in root, f"root CMake missing {token}")
check(root.index("if(KNETSENTRY_BUILD_DESKTOP)") < root.index("find_package(Qt6"),
      "Qt discovery not guarded by desktop option")
check("Qt6::" not in read("src/core/CMakeLists.txt"),
      "core must not depend on Qt")
check("Qt6::Core" in read("apps/desktop/CMakeLists.txt"),
      "Qt desktop must link actual Qt6::Core")
check("knetsentry_core_build_identity" in read("tests/CMakeLists.txt"),
      "expected real CTest smoke missing")
check("--version" in read("docs/development/BUILD_FOUNDATION.md"),
      "desktop command undocumented")
check("not" in read("docs/development/BUILD_FOUNDATION.md").lower(),
      "build status caveat missing")
check("CC-BY-SA-4.0" in read("docs/development/BUILD_FOUNDATION.md")[:160],
      "build guide SPDX missing")
try:
    data = json.loads(read("CMakePresets.json"))
    cfg = {p["name"]: p for p in data["configurePresets"]}
    builds = {p["name"] for p in data["buildPresets"]}
    tests = {p["name"] for p in data["testPresets"]}
    for name in ("linux-release", "linux-debug", "linux-core-only"):
        check(name in cfg and name in builds and name in tests,
              f"missing configure/build/test preset: {name}")
    check(cfg["linux-release"]["cacheVariables"]["KNETSENTRY_BUILD_DESKTOP"] == "ON",
          "release must require desktop")
    check(cfg["linux-core-only"]["cacheVariables"]["KNETSENTRY_BUILD_DESKTOP"] == "OFF",
          "core-only must explicitly disable Qt GUI")
    for preset in data["testPresets"]:
        check(preset.get("execution", {}).get("noTestsAction") == "error",
              f"{preset['name']}: empty test suites must fail")
except (KeyError, ValueError, TypeError) as exc:
    errors.append(f"invalid CMake preset structure: {exc}")
check("0.0.0" in root and "not a functioning siem" in read("docs/development/BUILD_FOUNDATION.md").lower(),
      "foundation version/status not clearly specified")
check("#include <QCoreApplication>" in read("apps/desktop/main.cpp"),
      "desktop program is not Qt-linked")
for rel in ("README.md", "docs/development/TOOLCHAIN_TEST_MATRIX.md",
            "docs/development/RELEASE_OBJECTIVES.md"):
    check("BUILD_FOUNDATION.md" in read(rel), f"{rel} missing build guide link")
check("MIT License" in read("LICENSE"), "root MIT license changed")
check("REUSE.toml" in {p.name for p in ROOT.iterdir()}, "REUSE metadata missing")
if errors:
    print("M1.1 build-foundation verification: FAIL", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    sys.exit(1)
print("M1.1 build-foundation verification: PASS")
print("  C++23 core + Qt desktop targets; 3 original configure/build/test presets")
print("  Qt/KDE required for desktop; runtime Kirigami test required (M1.3); core-only isolated")
print("  Full Ubuntu 26.04 Qt build and future security/GUI gates NOT verified here")

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.3 LSan scoped Qt/Kirigami suppressions and deliberate-leak gate.

Without arguments: validate source policy, NEVER imply runtime qualification.
With --probe: also require an instrumented, deliberately leaking C++ program
               to be rejected by LSan using the SAME scoped suppression file.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUPPRESSIONS = ROOT / "tests/sanitizers/lsan_qml_third_party.supp"
ERRORS: list[str] = []


def require(condition: bool, explanation: str) -> None:
    if not condition:
        ERRORS.append(explanation)


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        ERRORS.append(f"missing {relative}")
        return ""
    return path.read_text(encoding="utf-8")


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--probe", type=Path, help="Run test-only intentional leak; require LSan failure")
args = parser.parse_args()

rules = read("tests/sanitizers/lsan_qml_third_party.supp")
actual = [line.strip() for line in rules.splitlines()
          if line.strip() and not line.lstrip().startswith("#")]
require(actual == ["leak:libfontconfig.so.1", "leak:libKirigamiControlsplugin.so"],
        "unexpected LSan suppressions (only two observed external-library paths allowed)")
require("SPDX-License-Identifier: MIT" in rules[:120], "suppression file lacks MIT SPDX")

tests = read("tests/CMakeLists.txt")
require("if(KNETSENTRY_BUILD_DESKTOP)" in tests and
        "if(KNETSENTRY_ENABLE_SANITIZERS)" in tests,
        "QML suppression must depend on desktop and sanitizer options")
require(re.search(r"if\(KNETSENTRY_ENABLE_SANITIZERS\)\s+"
                  r"set_property\(TEST knetsentry_kirigami_qml_startup APPEND PROPERTY ENVIRONMENT\s+"
                  r'"LSAN_OPTIONS=suppressions=\$\{PROJECT_SOURCE_DIR\}/tests/sanitizers/'
                  r'lsan_qml_third_party\.supp:print_suppressions=1"\)', tests) is not None,
        "LSan suppression must be attached only to the actual Kirigami smoke test")
require("knetsentry_lsan_negative_control" in tests and
        "add_executable(knetsentry_lsan_probe sanitizers/lsan_probe.cpp)" in tests and
        "knetsentry_apply_project_options(knetsentry_lsan_probe)" in tests,
        "instrumented first-party leak negative control is missing")
require(re.search(r"if\(KNETSENTRY_ENABLE_SANITIZERS\)\s+"
                  r"add_executable\(knetsentry_lsan_probe", tests) is not None,
        "intentional leak fixture must only build with sanitizers")
require("--probe \"$<TARGET_FILE:knetsentry_lsan_probe>\"" in tests,
        "LSan negative control must execute the built probe")
require(tests.count("LSAN_OPTIONS=suppressions=") == 2,
        "LSan suppression must be restricted to QML smoke and negative-control tests")

probe = read("tests/sanitizers/lsan_probe.cpp")
require("SPDX-License-Identifier: MIT" in probe[:120], "probe lacks MIT SPDX")
require("std::malloc(1337)" in probe and "knetsentry_intentionally_leak_for_lsan_control" in probe,
        "intentional leak fixture must allocate an identifiable 1337-byte block")
require("__lsan_disable" not in probe and "__lsan_ignore_object" not in probe,
        "intentional leak fixture may not bypass LeakSanitizer")

try:
    presets = json.loads(read("CMakePresets.json"))
    mapping = {p["name"]: p for p in presets["testPresets"]}
    for name in ("linux-sanitize", "linux-sanitize-core-only"):
        opts = mapping[name]["environment"]["ASAN_OPTIONS"]
        require("detect_leaks=1" in opts and "detect_leaks=0" not in opts,
                f"{name} must keep leak detection enabled")
        require("LSAN_OPTIONS" not in mapping[name].get("environment", {}),
                f"{name} must not apply blanket LSan suppressions to the whole suite")
except (KeyError, ValueError, TypeError) as exc:
    ERRORS.append(f"invalid sanitizer presets: {exc}")

require("LSAN_OPTIONS=" not in read("cmake/KnetSentryBuildOptions.cmake"),
        "project-wide build configuration must not set LSan suppressions")

if args.probe:
    binary = args.probe.resolve()
    require(binary.is_file(), f"missing compiled intentional-leak fixture: {binary}")
    asan = os.environ.get("ASAN_OPTIONS", "")
    lsan = os.environ.get("LSAN_OPTIONS", "")
    require("detect_leaks=1" in asan,
            "negative control requires ASAN_OPTIONS=detect_leaks=1")
    require(f"suppressions={SUPPRESSIONS}" in lsan,
            "negative control must run under the same QML-only suppression file")
    if binary.is_file() and not ERRORS:
        result = subprocess.run([str(binary)], capture_output=True, text=True,
                                timeout=20, check=False)
        output = result.stdout + "\n" + result.stderr
        require(result.returncode != 0, "intentional first-party leak was not rejected")
        require("LeakSanitizer: detected memory leaks" in output,
                "negative control failed for a reason other than a reported LSan leak")
        require("Direct leak of 1337 byte(s)" in output,
                "expected 1337-byte first-party leak was not reported")

if ERRORS:
    print("M1.3 scoped LSan verification: FAIL", file=sys.stderr)
    for issue in ERRORS:
        print(f"  - {issue}", file=sys.stderr)
    sys.exit(1)
print("M1.3 scoped LSan verification: PASS")
print("  Exactly two external-library leak rules, scoped to Kirigami CTest only")
print("  Global ASan leak detection remains enabled; no broad suppressions")
if args.probe:
    print("  Deliberate 1337-byte first-party leak correctly detected and rejected")
else:
    print("  Source-only checks: Ubuntu Qt/LSan runtime outcome NOT verified")

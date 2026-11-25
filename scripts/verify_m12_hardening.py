#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.2 checks: source policy, and optionally compiled flags + executable ELF.

This script cannot establish that uninstrumented Qt/KDE libraries are safe, nor
can it replace inspection of exact release packages in M15.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ERRORS: list[str] = []


def require(ok: bool, msg: str) -> None:
    if not ok:
        ERRORS.append(msg)


def source(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        ERRORS.append(f"missing file: {rel}")
        return ""
    return path.read_text(encoding="utf-8")


def find_cache(cache: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}:[^=]+=(.*)$", cache, re.M)
    if not match:
        ERRORS.append(f"CMake cache is missing {name}")
        return ""
    return match.group(1).strip()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build-dir", type=Path,
                    help="Verify actual configured compile commands, link flags and built ELF files")
args = parser.parse_args()

module = source("cmake/KnetSentryBuildOptions.cmake")
root = source("CMakeLists.txt")
cmake_files = (
    "cmake/KnetSentryBuildOptions.cmake",
    "src/core/CMakeLists.txt", "src/service/CMakeLists.txt",
    "apps/manager/CMakeLists.txt", "apps/desktop/CMakeLists.txt",
    "src/agent/CMakeLists.txt", "apps/agent/CMakeLists.txt",
    "tests/CMakeLists.txt",
)
for rel in cmake_files:
    require(source(rel).startswith("# SPDX-FileCopyrightText: 2026 Chris Sutton\n"
                                   "# SPDX\x2dLicense-Identifier: BSD-2-Clause\n"),
            f"{rel} must use BSD-2-Clause SPDX header")
for rel, target in (("src/core/CMakeLists.txt", "knetsentry_core"),
                    ("src/service/CMakeLists.txt", "knetsentry_service"),
                    ("apps/manager/CMakeLists.txt", "knetsentryd"),
                    ("src/agent/CMakeLists.txt", "knetsentry_agent_lifecycle"),
                    ("apps/agent/CMakeLists.txt", "knetsentry-agent"),
                    ("apps/desktop/CMakeLists.txt", "knetsentry"),
                    ("tests/CMakeLists.txt", "knetsentry_core_smoke")):
    require(f"knetsentry_apply_project_options({target})" in source(rel),
            f"{target} lacks project-scoped options")
require("include(cmake/KnetSentryBuildOptions.cmake)" in root,
        "root must load project-scoped hardening module")
# Check that Clazy's compiler-specific OpenMP prerequisite has a clear,
# fail-closed diagnosis. This is a source check, not a Clazy runtime test.
for expected in (
    'CMAKE_CXX_COMPILER MATCHES "(^|/)clazy(-[0-9]+)?$"',
    "find_package(OpenMP QUIET COMPONENTS CXX)",
    "if(NOT OpenMP_CXX_FOUND)",
    "sudo apt install libomp-${_knetsentry_clang_major}-dev",
    "cmake --preset linux-clazy --fresh",
):
    require(expected in root, f"missing Clazy/OpenMP prerequisite guard: {expected}")
for forbidden in ("add_compile_options(", "add_link_options(",
                  "set(CMAKE_CXX_FLAGS", "set(CMAKE_EXE_LINKER_FLAGS"):
    require(forbidden not in root, f"root CMake unexpectedly uses global flags: {forbidden}")
for expected in (
    "KNETSENTRY_WARNINGS_AS_ERRORS", "KNETSENTRY_ENABLE_RELEASE_HARDENING",
    "KNETSENTRY_ENABLE_SANITIZERS", "KNETSENTRY_ENABLE_CLANG_TIDY",
    "-Werror", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion",
    "-fstack-protector-strong", "_FORTIFY_SOURCE=3", "LINKER:-z,relro",
    "LINKER:-z,now", "check_pie_supported", "POSITION_INDEPENDENT_CODE ON",
    "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
    "find_program(KNETSENTRY_CLANG_TIDY_EXECUTABLE",
    'message(FATAL_ERROR "clang-tidy requested but unavailable',
):
    require(expected in module, f"missing project policy: {expected}")

try:
    presets = json.loads(source("CMakePresets.json"))
    configure = {item["name"]: item for item in presets["configurePresets"]}
    builds = {item["name"] for item in presets["buildPresets"]}
    tests = {item["name"]: item for item in presets["testPresets"]}
    for name in ("linux-release", "linux-debug", "linux-core-only",
                 "linux-sanitize", "linux-sanitize-core-only", "linux-analysis", "linux-clazy"):
        require(name in configure and name in builds and name in tests,
                f"missing preset group {name}")
        if name in tests:
            require(tests[name].get("execution", {}).get("noTestsAction") == "error",
                    f"empty test suites accepted by {name}")
    require(configure["linux-sanitize"]["cacheVariables"]["KNETSENTRY_ENABLE_SANITIZERS"] == "ON",
            "sanitizer preset does not enable sanitizer instrumentation")
    require(configure["linux-sanitize-core-only"]["cacheVariables"]["KNETSENTRY_BUILD_DESKTOP"] == "OFF",
            "sanitizer core-only must exclude desktop")
    require(configure["linux-analysis"]["cacheVariables"]["KNETSENTRY_ENABLE_CLANG_TIDY"] == "ON",
            "analysis preset does not enable clang-tidy")
    require(configure["linux-clazy"]["cacheVariables"]["CMAKE_CXX_COMPILER"] == "clazy",
            "Qt-specific clazy compiler preset missing")
    for name in ("linux-sanitize", "linux-sanitize-core-only"):
        env = tests[name]["environment"]
        require("detect_leaks=1" in env["ASAN_OPTIONS"] and "halt_on_error=1" in env["UBSAN_OPTIONS"],
                f"sanitizer test environment incomplete: {name}")
except (ValueError, KeyError, TypeError) as exc:
    ERRORS.append(f"invalid preset configuration: {exc}")

# Verify the *applied* Release linker options, not merely successful flag probes.
for applied in ('"$<$<CONFIG:Release>:LINKER:-z,relro>"',
                '"$<$<CONFIG:Release>:LINKER:-z,now>"'):
    require(applied in module, f"hardening module does not apply {applied}")

require("knetsentry_build_hardening" in source("tests/CMakeLists.txt"),
        "actual build-evidence CTest missing")
require("HARDENING_AND_ANALYSIS.md" in source("docs/README.md") and
        "HARDENING_AND_ANALYSIS.md" in source("docs/development/TOOLCHAIN_TEST_MATRIX.md"),
        "hardening documentation not linked")
require("CC-BY-SA-4.0" in source("docs/development/HARDENING_AND_ANALYSIS.md")[:160],
        "hardening guide missing documentation license")

if args.build_dir:
    directory = args.build_dir.resolve()
    cache = directory / "CMakeCache.txt"
    database = directory / "compile_commands.json"
    ninja = directory / "build.ninja"
    require(cache.is_file() and database.is_file() and ninja.is_file(),
            f"missing configured Ninja compile evidence in {directory}")
    if cache.is_file() and database.is_file() and ninja.is_file():
        cache_text = cache.read_text(encoding="utf-8")
        build_type = find_cache(cache_text, "CMAKE_BUILD_TYPE")
        sanitizer = find_cache(cache_text, "KNETSENTRY_ENABLE_SANITIZERS") == "ON"
        desktop = find_cache(cache_text, "KNETSENTRY_BUILD_DESKTOP") == "ON"
        hardening = find_cache(cache_text, "KNETSENTRY_ENABLE_RELEASE_HARDENING") == "ON"
        warnings = find_cache(cache_text, "KNETSENTRY_WARNINGS_AS_ERRORS") == "ON"
        require(warnings, "build opts out of warnings-as-errors; cannot qualify M1.2")
        require(hardening, "build opts out of release hardening; cannot qualify M1.2")
        require(build_type in ("Debug", "Release"), f"unexpected build type: {build_type}")
        try:
            commands = json.loads(database.read_text(encoding="utf-8"))
        except (ValueError, TypeError) as exc:
            ERRORS.append(f"invalid compilation database: {exc}")
            commands = []
        source_names = ("build_info.cpp", "core_smoke.cpp", "lifecycle.cpp", "main.cpp",
                        "agent_main.cpp", "agent_lifecycle_m51.cpp", "enrollment.cpp", "enrollment_admission.cpp", "agent_roster.cpp", "agent_roster_m47.cpp", "enrollment_admin.cpp", "enrollment_m44.cpp", "agent_health.cpp")
        for filename in source_names:
            entries = [item for item in commands if Path(item["file"]).name == filename]
            require(len(entries) >= 1, f"no actual compile command for {filename}")
            for entry in entries:
                command = entry.get("command", " ".join(entry.get("arguments", [])))
                for flag in ("-Werror", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion"):
                    require(flag in command, f"{filename} missing {flag}")
                require("-fPIC" in command or "-fPIE" in command,
                        f"{filename} missing PIC/PIE compiler option")
                if sanitizer:
                    for flag in ("-fsanitize=address,undefined", "-fno-omit-frame-pointer"):
                        require(flag in command, f"{filename} missing {flag}")
                else:
                    require("-fsanitize=" not in command, f"unexpected instrumentation in {filename}")
                if build_type == "Release":
                    require("-fstack-protector-strong" in command,
                            f"{filename} missing Release stack protector")
                    require("-D_FORTIFY_SOURCE=3" in command,
                            f"{filename} missing Release fortify")
        ninja_text = ninja.read_text(encoding="utf-8")
        if sanitizer:
            require("-fsanitize=address,undefined" in ninja_text,
                    "link flags missing ASan/UBSan runtime")
        if build_type == "Release":
            for flag in ("-z,relro", "-z,now"):
                require(flag in ninja_text, f"Release linker flags missing {flag}")
        executables = [directory / "tests/knetsentry_core_smoke",
                       directory / "apps/manager/knetsentryd",
                       directory / "apps/agent/knetsentry-agent",
                       directory / "tests/knetsentry_agent_lifecycle_test",
                       directory / "src/core/knetsentry-enrollment",
                       directory / "tests/knetsentry_enrollment_test"]
        if desktop:
            executables.append(directory / "apps/desktop/knetsentry")
        for exe in executables:
            require(exe.is_file(), f"missing built test/application executable: {exe}")
            if exe.is_file() and build_type == "Release" and sys.platform.startswith("linux"):
                readelf = shutil.which("readelf")
                require(readelf is not None, "readelf (binutils) required for ELF hardening verification")
                if readelf:
                    header = subprocess.run([readelf, "-hW", str(exe)], capture_output=True, text=True)
                    segments = subprocess.run([readelf, "-lW", str(exe)], capture_output=True, text=True)
                    dynamic = subprocess.run([readelf, "-dW", str(exe)], capture_output=True, text=True)
                    require(all(p.returncode == 0 for p in (header, segments, dynamic)),
                            f"readelf failed: {exe}")
                    require(bool(re.search(r"Type:\s+DYN\b", header.stdout)),
                            f"PIE ELF type not found: {exe}")
                    require("GNU_RELRO" in segments.stdout, f"GNU_RELRO not found: {exe}")
                    require("BIND_NOW" in dynamic.stdout or
                            bool(re.search(r"\bNOW\b", dynamic.stdout)),
                            f"BIND_NOW not found: {exe}")
                    for line in segments.stdout.splitlines():
                        if "GNU_STACK" in line:
                            require("E" not in line.split()[-2],
                                    f"executable stack detected: {exe}")

if ERRORS:
    print("M1.2 hardening verification: FAIL", file=sys.stderr)
    for err in ERRORS:
        print(f"  - {err}", file=sys.stderr)
    sys.exit(1)
print("M1.2 hardening verification: PASS")
print("  First-party warnings, release hardening, ASan/UBSan and optional analysis presets defined")
if args.build_dir:
    print(f"  Checked configured compilation/link evidence and built binaries: {args.build_dir}")
else:
    print("  Source-only mode: compiler flags, ELF and Ubuntu Qt build NOT verified")

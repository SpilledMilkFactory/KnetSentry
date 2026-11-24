#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.7 structural and configured CTest inventory contract.

Source-only checks do not qualify a build. --build-dir inspects the real
CMake cache and CTest discovery, rejecting zero/missing/incorrectly-scoped tests.
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
CORE_TESTS = {
    "knetsentry_core_build_identity", "knetsentry_structured_diagnostics",
    "knetsentry_core_boundary_contract", "knetsentry_configuration_contract",
    "knetsentry_build_hardening",
    "knetsentry_manager_state_contract", "knetsentry_manager_signal_lifecycle",
    "knetsentry_manager_configuration_contract", "knetsentry_manager_configuration_runtime",
    "knetsentry_local_ipc_authorization_contract", "knetsentry_local_ipc_runtime",
    "knetsentry_service_health_contract", "knetsentry_service_health_runtime",
    "knetsentry_service_audit_contract", "knetsentry_service_audit_runtime",
    "knetsentry_health_client_contract", "knetsentry_health_client_runtime",
}
DESKTOP_TESTS = {
    "knetsentry_desktop_version", "knetsentry_kirigami_qml_startup",
    "knetsentry_primary_navigation", "knetsentry_qt_model_contract",
    "knetsentry_qt_health_model",
}
NONSAN_DESKTOP_TESTS = {
    "knetsentry_navigation_qml_diagnostics", "knetsentry_visual_system",
    "knetsentry_desktop_diagnostic_lifecycle", "knetsentry_qt_application_lifecycle",
    "knetsentry_gui_health_runtime",
}
SANITIZER_TEST = "knetsentry_lsan_negative_control"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_cache(cache: Path) -> dict[str, str]:
    require(cache.is_file(), f"missing CMakeCache: {cache}")
    result: dict[str, str] = {}
    for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith(("#", "//")) or "=" not in line:
            continue
        key_type, value = line.split("=", 1)
        result[key_type.split(":", 1)[0]] = value
    return result


def is_on(cache: dict[str, str], name: str) -> bool:
    require(name in cache, f"required CMake option absent: {name}")
    require(cache[name] in {"ON", "OFF"}, f"invalid CMake boolean: {name}")
    return cache[name] == "ON"


def source_contract() -> None:
    tests = (ROOT / "tests/CMakeLists.txt").read_text()
    desktop = (ROOT / "apps/desktop/CMakeLists.txt").read_text()
    model = (ROOT / "apps/desktop/section_catalog_model.cpp").read_text()
    qt_model_test = (ROOT / "tests/qt/section_catalog_qtest.cpp").read_text()
    qt_app_test = (ROOT / "tests/qt/application_qtest.cpp").read_text()
    presets = (ROOT / "CMakePresets.json").read_text()
    for name in CORE_TESTS | DESKTOP_TESTS | NONSAN_DESKTOP_TESTS | {SANITIZER_TEST}:
        require(f"NAME {name}" in tests, f"CTest registration missing: {name}")
    for pattern, value in [
        ("find_package(Qt6 REQUIRED COMPONENTS Test)", tests),
        ("QAbstractItemModelTester", qt_model_test),
        ("QSignalSpy", qt_model_test),
        ("QTEST_GUILESS_MAIN", qt_app_test),
        ("QProcess", qt_app_test),
        ("AUTOMOC ON", tests),
        ("knetsentry_apply_project_options(knetsentry_qt_model_test)", tests),
        ("knetsentry_apply_project_options(knetsentry_qt_application_test)", tests),
        ("knetsentry_apply_project_options(knetsentry_section_catalog)", desktop),
        ("QAbstractListModel", (ROOT / "apps/desktop/section_catalog_model.hpp").read_text()),
        ("return {}", model),
        ('"noTestsAction": "error"', presets),
        ('"detect_leaks=1', presets),
    ]:
        require(pattern in value, f"missing test hardening or model contract: {pattern}")
    require(tests.index("find_package(Qt6 REQUIRED COMPONENTS Test)") >
            tests.index("if(KNETSENTRY_BUILD_DESKTOP)"),
            "Qt Test dependency must be limited to desktop-enabled builds")
    require("if(NOT KNETSENTRY_ENABLE_SANITIZERS)" in tests,
            "unqualified QML subprocess test must not expand LSan scope")
    require("knetsentry_configuration_contract" in tests,
            "configured CTest inventory gate must be mandatory")
    # M1.7 regression: QAbstractListModel::columnCount is private on Qt 6;
    # call via QAbstractItemModel's public virtual interface instead.
    require("model.columnCount()" not in qt_model_test,
            "invalid Qt 6 QAbstractListModel::columnCount() direct call")
    require("itemModel.columnCount()" in qt_model_test and
            "const QAbstractItemModel& itemModel = model;" in qt_model_test,
            "Qt model test must exercise the public abstract item-model interface")
    core_test = (ROOT / "tests/core_contract_m17.cpp").read_text()
    require("std::bit_cast<DiagnosticEvent>" in core_test and
            "static_cast<DiagnosticEvent>(255)" not in core_test,
            "invalid diagnostic event test must not trigger analyzer enum-cast warning")


def configured_contract(path: Path) -> tuple[int, bool, bool]:
    cache = read_cache(path / "CMakeCache.txt")
    require(is_on(cache, "BUILD_TESTING"), "BUILD_TESTING=OFF is not M1.7-qualified")
    require(is_on(cache, "KNETSENTRY_WARNINGS_AS_ERRORS"),
            "first-party warnings-as-errors disabled")
    require(is_on(cache, "KNETSENTRY_ENABLE_RELEASE_HARDENING"),
            "binary hardening disabled")
    desktop = is_on(cache, "KNETSENTRY_BUILD_DESKTOP")
    sanitize = is_on(cache, "KNETSENTRY_ENABLE_SANITIZERS")
    require(not (sanitize and cache.get("CMAKE_BUILD_TYPE") == "Release"),
            "sanitizers incompatible with Release configuration")
    result = subprocess.run(["ctest", "--test-dir", str(path), "-N"],
                            capture_output=True, text=True, check=False, timeout=15)
    require(result.returncode == 0, f"CTest discovery failed: {result.stderr[:200]}")
    names = re.findall(r"^\s*Test\s+#\d+:\s+(\S+)", result.stdout, re.MULTILINE)
    require(len(names) == len(set(names)), "duplicate CTest registrations")
    require(names, "zero-test CTest inventory cannot qualify M1.7")
    expected = CORE_TESTS.copy()
    if desktop:
        expected.update(DESKTOP_TESTS)
        if not sanitize:
            expected.update(NONSAN_DESKTOP_TESTS)
    if sanitize:
        expected.add(SANITIZER_TEST)
    require(set(names) == expected,
            "CTest inventory mismatch: missing=" + repr(sorted(expected - set(names))) +
            ", unexpected=" + repr(sorted(set(names) - expected)))

    # ctest -N can list registered tests even when compilation FAILED and
    # their binaries were never created. Inspect CTest's machine-readable
    # command discovery and require every registered executable to exist.
    discovery = subprocess.run(
        ["ctest", "--test-dir", str(path), "--show-only=json-v1"],
        capture_output=True, text=True, check=False, timeout=15)
    require(discovery.returncode == 0, "CTest JSON discovery failed")
    try:
        discovered = json.loads(discovery.stdout)["tests"]
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError(f"invalid CTest JSON inventory: {error}") from error
    require(len(discovered) == len(names), "CTest JSON and text inventories disagree")
    require({test.get("name") for test in discovered} == expected,
            "CTest JSON names do not match required inventory")
    for test in discovered:
        command = test.get("command")
        require(isinstance(command, list) and command and isinstance(command[0], str),
                f"CTest executable missing (build incomplete): {test.get('name')}")
        executable = Path(command[0])
        require(executable.is_file() and os.access(executable, os.X_OK),
                f"CTest executable not built or not executable: {test.get('name')}")
    return len(names), desktop, sanitize


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build-dir", type=Path, help="Require real configured CTest inventory")
    args = p.parse_args()
    try:
        source_contract()
        if args.build_dir:
            count, desktop, sanitized = configured_contract(args.build_dir.resolve())
            print("M1.7 test-suite verification: PASS")
            print(f"  Real CTest inventory: {count} required tests; desktop={desktop}; sanitized={sanitized}")
            print("  All required CTest commands resolve to built executables")
            print("  Discovery/build evidence only: individual tests must still pass CTest")
        else:
            print("M1.7 test-suite verification: PASS (source-only)")
            print("  C++ unit, Qt Test model/application, QML and configuration gates defined")
            print("  Actual configured and executed test results NOT verified here")
        return 0
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"M1.7 test-suite verification: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

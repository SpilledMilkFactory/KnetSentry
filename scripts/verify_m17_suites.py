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
    "knetsentry_agent_protocol_contract",
    "knetsentry_agent_lifecycle_contract", "knetsentry_agent_service_runtime",
    "knetsentry_journal_collection_contract", "knetsentry_authentication_collection_contract", "knetsentry_audit_collection_contract", "knetsentry_telemetry_delivery_contract",
    "knetsentry_file_integrity_contract", "knetsentry_privacy_policy_contract",
    "knetsentry_collector_recovery_contract",
    "knetsentry_telemetry_status_contract", "knetsentry_telemetry_status_runtime",
    "knetsentry_event_ingestion_contract", "knetsentry_event_normalization_contract",
    "knetsentry_event_storage_contract", "knetsentry_sqlite_storage_contract", "knetsentry_evidence_integrity_contract", "knetsentry_event_search_contract", "knetsentry_storage_retention_contract",
    "knetsentry_event_explorer_contract", "knetsentry_event_explorer_runtime",
    "knetsentry_storage_recovery_contract", "knetsentry_ingestion_recovery_contract",
    "knetsentry_split_storage_contract", "knetsentry_detection_contract", "knetsentry_rule_schema_contract", "knetsentry_authentication_patterns_contract", "knetsentry_system_integrity_contract", "knetsentry_scheduler_contract", "knetsentry_alerts_contract", "knetsentry_alert_interface_contract", "knetsentry_alert_interface_runtime", "knetsentry_detection_recovery_contract", "knetsentry_technique_mappings_contract", "knetsentry_dashboard_summary_contract",
    "knetsentry_identity_contract", "knetsentry_tls_contract",
    "knetsentry_enrollment_contract", "knetsentry_enrollment_admin",
    "knetsentry_credential_lifecycle",
    "knetsentry_agent_health_contract",
    "knetsentry_authentication_transport_regression",
    "knetsentry_agent_roster_contract", "knetsentry_agent_roster_runtime",
    "knetsentry_core_boundary_contract", "knetsentry_configuration_contract",
    "knetsentry_build_hardening", "knetsentry_network_scope_policy",
    "knetsentry_network_prefix_validation", "knetsentry_network_topology_awareness",
    "knetsentry_network_fail_closed_authorization", "knetsentry_firewall_profile_contract",
    "knetsentry_network_isolation_fixture", "knetsentry_network_adversarial_boundary",
    "knetsentry_manager_state_contract", "knetsentry_manager_signal_lifecycle",
    "knetsentry_manager_configuration_contract", "knetsentry_manager_configuration_runtime",
    "knetsentry_local_ipc_authorization_contract", "knetsentry_local_ipc_runtime",
    "knetsentry_service_health_contract", "knetsentry_service_health_runtime",
    "knetsentry_service_audit_contract", "knetsentry_service_audit_runtime",
    "knetsentry_health_client_contract", "knetsentry_health_client_runtime",
    "knetsentry_systemd_policy_contract", "knetsentry_service_lifecycle_ipc_integration",
}
DESKTOP_TESTS = {
    "knetsentry_desktop_version", "knetsentry_kirigami_qml_startup",
    "knetsentry_primary_navigation", "knetsentry_qt_model_contract",
    "knetsentry_qt_health_model", "knetsentry_qt_daemon_control",
}
NONSAN_DESKTOP_TESTS = {
    "knetsentry_navigation_qml_diagnostics", "knetsentry_visual_system",
    "knetsentry_desktop_diagnostic_lifecycle", "knetsentry_qt_application_lifecycle",
    "knetsentry_gui_health_runtime", "knetsentry_gui_daemon_toolbar",
    "knetsentry_gui_telemetry_runtime", "knetsentry_gui_event_explorer_runtime", "knetsentry_gui_alert_interface_runtime", "knetsentry_gui_dashboard_runtime",
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

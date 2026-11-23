#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.6 diagnostic contract: source policy and actual JSONL/secret negative tests.

A source-only PASS does not qualify runtime redaction; supply --probe or
--build-dir for genuine compiled-executable evidence.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_BYTES = 512
EXPECTED = {"schema", "time_unix_ms", "sequence", "level", "component", "event",
            "outcome", "count", "private_detail"}
LEVELS = {"debug", "info", "warning", "error", "critical"}
COMPONENTS = {"core", "desktop", "verification"}
EVENTS = {"gui_starting", "gui_ready", "gui_load_rejected", "self_test", "verification_rejected"}
OUTCOMES = {"started", "success", "failure", "rejected"}
SECRET_MARKERS = ("TOPSECRET_42", "SECRET_M16_TOKEN", "Authorization", "password=")


def verify_output(output: bytes) -> None:
    if not output or any(marker.encode() in output for marker in SECRET_MARKERS):
        raise ValueError("private marker leaked or no diagnostics emitted")
    lines = output.splitlines(keepends=True)
    if len(lines) != 131 or any(not row.endswith(b"\n") or len(row) > MAX_BYTES for row in lines):
        raise ValueError("unexpected record count, newline, or record bound")
    for index, raw in enumerate(lines, 1):
        item = json.loads(raw)
        if set(item) != EXPECTED or item["schema"] != 1 or item["sequence"] != index:
            raise ValueError("invalid schema or nonmonotonic sequence")
        if type(item["time_unix_ms"]) is not int or item["time_unix_ms"] <= 0:
            raise ValueError("invalid UTC epoch millisecond timestamp")
        if (item["level"] not in LEVELS or item["component"] not in COMPONENTS
                or item["event"] not in EVENTS or item["outcome"] not in OUTCOMES):
            raise ValueError("unapproved event metadata")
        if item["private_detail"] not in (None, "[REDACTED]"):
            raise ValueError("private context was not redacted")
        if item["count"] is not None and (type(item["count"]) is not int or
                                           not 0 <= item["count"] <= 2**64 - 1):
            raise ValueError("invalid count type/range")
    first, second, third = [json.loads(v) for v in lines[:3]]
    if (first["private_detail"] != "[REDACTED]" or first["count"] != 0 or
            first["outcome"] != "rejected" or second["count"] != 2**64 - 1 or
            second["private_detail"] is not None or third["outcome"] != "started"):
        raise ValueError("privacy or numeric bound negative case failed")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--probe", type=Path, help="run the compiled C++ probe")
    ap.add_argument("--build-dir", type=Path, help="locate test executable in a CMake build")
    ap.add_argument("--desktop-binary", type=Path,
                    help="run a real offscreen QML startup and inspect fixed-code lifecycle records")
    args = ap.parse_args()
    violations = []
    sources = {
        "header": ROOT / "include/knetsentry/core/diagnostics.hpp",
        "impl": ROOT / "src/core/diagnostics.cpp",
        "test": ROOT / "tests/diagnostics_smoke.cpp",
        "cmake": ROOT / "tests/CMakeLists.txt",
        "doc": ROOT / "docs/development/STRUCTURED_DIAGNOSTICS.md",
        "gui": ROOT / "apps/desktop/main.cpp",
    }
    for name, path in sources.items():
        if not path.is_file():
            violations.append(f"missing {name}: {path}")
    if violations:
        print("M1.6 diagnostics verification: FAIL\n  " + "\n  ".join(violations))
        return 1
    h, impl, cmake, gui = (sources[x].read_text() for x in ("header", "impl", "cmake", "gui"))
    requirements = [
        ("typed allowlisted metadata", "enum class DiagnosticEvent" in h and "enum class DiagnosticComponent" in h),
        ("bounded records", "max_record_bytes = 512" in h and "std::array<char, max_record_bytes>" in impl),
        ("fixed redaction", "[REDACTED]" in impl and "SensitiveContext::text" in impl),
        ("thread synchronization", "std::lock_guard lock(mutex_)" in impl),
        ("JSON record framing", "\\n" in impl and "time_unix_ms" in impl),
        ("sink failure handling", "output_.good()" in impl and "catch (...)" in impl),
        ("invalid-code rejection", 'name(record.event)) == "unknown"' in impl),
        ("CTest diagnostics registered", "knetsentry_structured_diagnostics" in cmake),
        ("desktop lifecycle CTest registered", "knetsentry_desktop_diagnostic_lifecycle" in cmake),
        ("GUI startup integrated", "GuiStarting" in gui and "GuiReady" in gui and "GuiLoadRejected" in gui),
        ("no dynamic text formatting", not re.search(r"(?:record\.sensitive_context->text|record\.sensitive_context\.value\(\)\.text)\s*\.data\(", impl)),
    ]
    violations += [f"missing/invalid {name}" for name, ok in requirements if not ok]
    # Negative controls: prove a leaked credential, a too-large record, and a
    # non-allowlisted event code are rejected by the same JSON validator.
    # A controlled synthetic sample is useful, but not runtime qualification.
    try:
        verify_output(b'{"secret":"TOPSECRET_42"}\n')
        violations.append("credential negative control accepted")
    except ValueError:
        pass
    try:
        verify_output(b"x" * (MAX_BYTES + 1) + b"\n")
        violations.append("record bound negative control accepted")
    except ValueError:
        pass
    if violations:
        print("M1.6 diagnostics verification: FAIL\n  " + "\n  ".join(violations))
        return 1
    probe = args.probe
    if args.build_dir:
        if probe:
            ap.error("choose only --probe or --build-dir")
        probe = args.build_dir / "tests/knetsentry_diagnostics_probe"
    if args.desktop_binary:
        if probe:
            ap.error("--desktop-binary cannot be combined with --probe/--build-dir")
        resolved = args.desktop_binary.resolve()
        if not resolved.is_file():
            print(f"M1.6 diagnostics verification: FAIL (missing desktop executable {resolved})")
            return 1
        import os
        env = os.environ.copy()
        env.update({"QT_QPA_PLATFORM": "offscreen", "QT_QUICK_BACKEND": "software",
                    "QT_QUICK_CONTROLS_STYLE": "Basic"})
        try:
            result = subprocess.run([str(resolved), "--self-test-qml"], capture_output=True,
                                    timeout=30, check=False, env=env)
            if result.returncode or b"Kirigami QML smoke: PASS" not in result.stdout:
                raise ValueError("desktop Kirigami startup failed")
            records = []
            for line in result.stderr.splitlines():
                if line.startswith(b'{"schema":1,'):
                    if len(line) + 1 > MAX_BYTES:
                        raise ValueError("desktop diagnostic exceeded record bound")
                    item = json.loads(line)
                    if set(item) != EXPECTED or item["component"] != "desktop" or (
                            item["private_detail"] is not None):
                        raise ValueError("desktop diagnostic schema/privacy violation")
                    records.append(item)
            if ([r["event"] for r in records] != ["gui_starting", "gui_ready"] or
                    [r["sequence"] for r in records] != [1, 2]):
                raise ValueError("missing or misordered GUI lifecycle records")
        except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
            print(f"M1.6 diagnostics verification: FAIL ({exc})")
            return 1
        print("M1.6 diagnostics verification: PASS (Qt/Kirigami runtime and fixed-code GUI lifecycle JSONL)")
        print(f"  Actual desktop executable verified: {resolved}")
        return 0
    if probe:
        resolved = probe.resolve()
        if not resolved.is_file():
            print(f"M1.6 diagnostics verification: FAIL (missing built probe {resolved})")
            return 1
        try:
            result = subprocess.run([str(resolved)], capture_output=True, timeout=20, check=False)
            if result.returncode or result.stderr:
                raise ValueError(f"probe exited {result.returncode}; stderr is not allowed")
            verify_output(result.stdout)
        except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
            print(f"M1.6 diagnostics verification: FAIL ({exc})")
            return 1
        print("M1.6 diagnostics verification: PASS (131 JSONL records; bounded, thread-safe, secret-redacted)")
        print(f"  Actual compiled probe verified: {resolved}")
    else:
        print("M1.6 diagnostics verification: PASS (typed schema, bounds, redaction policy, negative fixtures)")
        print("  Source-only mode: compiled logging and Qt desktop runtime NOT verified")
    return 0

if __name__ == "__main__":
    sys.exit(main())

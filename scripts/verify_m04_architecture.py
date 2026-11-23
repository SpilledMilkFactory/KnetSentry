#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M0.4 static architecture traceability validation (no network/system effects)."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
ARCH = ROOT / "docs/architecture"
SEC = ROOT / "docs/security"

FILES = [
    "SYSTEM_ARCHITECTURE.md", "COMPONENT_CATALOG.md", "INTERFACE_CONTRACTS.md",
    "DEPLOYMENT_TOPOLOGIES.md", "ARCHITECTURE_TRACEABILITY.md",
    "adr/0001-security-process-boundaries.md",
    "adr/0002-telemetry-trust-and-evidence.md",
    "adr/0003-network-egress-and-response.md",
    "adr/0004-qt-desktop-boundaries.md",
]


def ids_table(text: str, prefix: str, digits: int) -> list[str]:
    return re.findall(r"^\| `(" + prefix + r"-\d{" + str(digits) + r"})`(?:\s|\|)", text, re.M)


def check_set(name: str, found: list[str], expected: set[str], errors: list[str]) -> None:
    if len(set(found)) != len(found):
        errors.append(f"{name}: duplicated IDs")
    if set(found) != expected:
        errors.append(f"{name}: missing={sorted(expected - set(found))} extra={sorted(set(found) - expected)}")


def verify() -> list[str]:
    errors: list[str] = []
    files = [ARCH / name for name in FILES]
    sources = [SEC / "THREAT_MODEL.md", SEC / "THREAT_REGISTER.md", SEC / "THREAT_VERIFICATION_MATRIX.md",
               SEC / "NETWORK_SCOPE_REQUIREMENTS.md"]
    for p in files + sources:
        if not p.is_file():
            errors.append(f"Missing document: {p.relative_to(ROOT)}")
    if errors:
        return errors
    comp, inter, trace = ((ARCH / f).read_text(encoding="utf-8") for f in
                          ("COMPONENT_CATALOG.md", "INTERFACE_CONTRACTS.md", "ARCHITECTURE_TRACEABILITY.md"))
    threat_model, register, matrix, network = (p.read_text(encoding="utf-8") for p in sources)

    components = set(f"C-{n:02d}" for n in range(1, 22))
    processes = set(f"P-{n:02d}" for n in range(1, 13))
    interfaces = set(f"I-{n:02d}" for n in range(1, 24))
    boundaries = set(f"TB-{n:02d}" for n in range(1, 13))
    threats = set(f"TH-{n:03d}" for n in range(1, 43))
    requirements = set(f"KS-NET-{n:03d}" for n in range(1, 43))
    tests = set(f"TV-{n:02d}" for n in range(1, 31))

    check_set("Component catalog", ids_table(comp, "C", 2), components, errors)
    check_set("Process privilege matrix", ids_table(comp, "P", 2), processes, errors)
    check_set("Interface registry", ids_table(inter, "I", 2), interfaces, errors)
    check_set("M0.4 boundary owners", ids_table(trace, "TB", 2), boundaries, errors)
    check_set("M0.4 threat mappings", ids_table(trace, "TH", 3), threats, errors)
    check_set("M0.4 requirement mappings", ids_table(trace, "KS-NET", 3), requirements, errors)
    check_set("M0.3 boundaries", ids_table(threat_model, "TB", 2), boundaries, errors)
    check_set("M0.3 threats", ids_table(register, "TH", 3), threats, errors)
    check_set("M0.2 requirements", ids_table(network, "KS-NET", 3), requirements, errors)
    check_set("M0.3 tests", ids_table(matrix, "TV", 2), tests, errors)

    # All architectural trace rows must name existing components and interfaces.
    for line in trace.splitlines():
        if not re.match(r"^\| `(TB-|TH-|KS-NET-)", line):
            continue
        cols = [s.strip() for s in line.strip().strip("|").split("|")]
        if len(cols) < 4:
            errors.append(f"Incomplete trace row: {line[:90]}")
            continue
        owners = re.findall(r"C-\d{2}", cols[2] if cols[0].lstrip("`").startswith("TH-") else cols[1])
        if not owners:
            errors.append(f"Missing component owner in {cols[0]}")
        for ref in owners:
            if ref not in components: errors.append(f"Unknown component: {ref} in {cols[0]}")
        iface_cell = cols[3] if cols[0].lstrip("`").startswith("TH-") else cols[2]
        refs = re.findall(r"I-\d{2}", iface_cell)
        if not refs or any(r not in interfaces for r in refs):
            errors.append(f"Missing/unknown interface in {cols[0]}")
        if not re.search(r"M\d+(?:\.\d+)?", line):
            errors.append(f"No milestone owner in {cols[0]}")

    baseline_th = re.findall(r"^\| `(TH-\d{3})` \| `(TB-\d{2})` \|", register, re.M)
    map_th = re.findall(r"^\| `(TH-\d{3})` \| `(TB-\d{2})` \|", trace, re.M)
    if sorted(baseline_th) != sorted(map_th):
        errors.append("Threat-to-boundary mapping differs from M0.3 register")
    register_rows = re.findall(r"^\| `(TH-\d{3})` \| `(TB-\d{2})` \|([^\n]+)$", register, re.M)
    trace_rows = re.findall(r"^\| `(TH-\d{3})` \| `(TB-\d{2})` \|([^\n]+)$", trace, re.M)
    baseline_test_map = {tid: set(re.findall(r"TV-\d{2}", rest)) for tid, _tb, rest in register_rows}
    for tid, _tb, rest in trace_rows:
        mapped = set(re.findall(r"TV-\d{2}", rest))
        if mapped != baseline_test_map.get(tid, set()) or not mapped <= tests:
            errors.append(f"{tid}: future test mapping differs from M0.3 register")

    arch_files = files + [ROOT / "README.md", ROOT / "PRODUCT_VISION.md",
                          ROOT / "docs/architecture/PRODUCT_SCOPE.md",
                          ROOT / "docs/architecture/NETWORK_COMMUNICATION_MATRIX.md",
                          ROOT / "docs/security/SECURITY_PRINCIPLES.md",
                          ROOT / "docs/security/THREAT_MODEL.md",
                          ROOT / "docs/security/THREAT_VERIFICATION_MATRIX.md",
                          ROOT / "docs/development/RELEASE_OBJECTIVES.md"]
    for path in arch_files:
        body = path.read_text(encoding="utf-8")
        if "SPDX-License-Identifier: CC-BY-SA-4.0" not in body and path in files:
            errors.append(f"Missing document SPDX metadata: {path.relative_to(ROOT)}")
        for raw in re.findall(r"\]\(([^)]+)\)", body):
            target = raw.split(" ", 1)[0]
            parsed = urlparse(target)
            if parsed.scheme or parsed.netloc or target.startswith("#"):
                continue
            resolved = (path.parent / unquote(parsed.path)).resolve()
            if not resolved.is_relative_to(ROOT.resolve()) or not resolved.is_file():
                errors.append(f"Broken/unsafe link in {path.relative_to(ROOT)}: {target}")

    system = (ARCH / "SYSTEM_ARCHITECTURE.md").read_text(encoding="utf-8").lower()
    deployments = (ARCH / "DEPLOYMENT_TOPOLOGIES.md").read_text(encoding="utf-8").lower()
    for token in ["agentless", "optional host", "unprivileged", "qt 6", "public", "confidence", "unverified"]:
        if token not in system:
            errors.append(f"System architecture missing requirement: {token}")
    for token in ["printer", "doorbell", "no agent", "mirror", "coverage", "feed"]:
        if token not in deployments:
            errors.append(f"Deployment profiles missing example: {token}")
    for token in ["no network", "raw", "no direct", "no ai", "sql"]:
        if token not in comp.lower() + inter.lower():
            errors.append(f"Missing dependency/security guardrail: {token}")
    return errors


if __name__ == "__main__":
    problems = verify()
    if problems:
        print("M0.4 architecture verification: FAIL", file=sys.stderr)
        for item in problems:
            print(f"  - {item}", file=sys.stderr)
        raise SystemExit(1)
    print("M0.4 architecture verification: PASS")
    print("  21 component roles, 12 process roles, 23 logical interfaces")
    print("  12 trust boundaries, 42 M0.3 threats, 42 M0.2 network requirements")
    print("  Existing M0.3 risk and security tests remain unimplemented")

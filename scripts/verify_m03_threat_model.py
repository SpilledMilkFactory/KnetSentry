#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Static M0.3 document-integrity checks; no network or system changes."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
THREAT_DIR = ROOT / "docs" / "security"
MODEL = THREAT_DIR / "THREAT_MODEL.md"
REGISTER = THREAT_DIR / "THREAT_REGISTER.md"
MATRIX = THREAT_DIR / "THREAT_VERIFICATION_MATRIX.md"
NETWORK = THREAT_DIR / "NETWORK_SCOPE_REQUIREMENTS.md"


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def exact_range(ids: set[str], prefix: str, count: int, errors: list[str]) -> None:
    expected = {f"{prefix}{i:03d}" for i in range(1, count + 1)}
    if ids != expected:
        fail(errors, f"{prefix}: missing {sorted(expected - ids)}, extra {sorted(ids - expected)}")


def verify() -> list[str]:
    errors: list[str] = []
    documents = [MODEL, REGISTER, MATRIX, NETWORK]
    for path in documents:
        if not path.is_file():
            fail(errors, f"Missing required document: {path.relative_to(ROOT)}")
    if errors:
        return errors

    model = MODEL.read_text(encoding="utf-8")
    register = REGISTER.read_text(encoding="utf-8")
    matrix = MATRIX.read_text(encoding="utf-8")
    net = NETWORK.read_text(encoding="utf-8")

    threat_rows = re.findall(r"^\| `(TH-\d{3})` \| `(TB-\d{2})` \|([^\n]+)$", register, re.M)
    ids = [tid for tid, _, _ in threat_rows]
    if len(ids) != len(set(ids)):
        fail(errors, "Duplicate threat-register IDs")
    exact_range(set(ids), "TH-", 42, errors)
    boundaries = set(re.findall(r"^\| `(TB-\d{2})` ", model, re.M))
    if boundaries != {f"TB-{n:02d}" for n in range(1, 13)}:
        fail(errors, "Expected twelve distinct trust boundaries TB-01..TB-12")
    test_ids = re.findall(r"^\| `(TV-\d{2})` \|", matrix, re.M)
    if len(test_ids) != len(set(test_ids)):
        fail(errors, "Duplicate verification test IDs")
    if set(test_ids) != {f"TV-{n:02d}" for n in range(1, 31)}:
        fail(errors, "Expected thirty unique verification IDs TV-01..TV-30")

    requirement_ids = set(re.findall(r"^\| `(KS-NET-\d{3})` \|", net, re.M))
    exact_range(requirement_ids, "KS-NET-", 42, errors)

    for tid, boundary, rest in threat_rows:
        if boundary not in boundaries:
            fail(errors, f"{tid}: unknown boundary {boundary}")
        cells = rest.strip().split(" | ")
        # STRIDE, scenario, likelihood, impact, score, mitigation, contract, owner, test
        if len(cells) != 9:
            fail(errors, f"{tid}: expected 11 table cells, found {len(cells) + 2}")
            continue
        stride, scenario, likelihood, impact, screen, mitigation, contract, owner, tests = cells
        if not scenario.strip() or not mitigation.strip() or not owner.strip():
            fail(errors, f"{tid}: missing scenario, mitigation, or owner")
        if not set(stride.strip().split("/")) <= set("STRIDE"):
            fail(errors, f"{tid}: unexpected STRIDE classification {stride}")
        try:
            score = int(likelihood) * int(impact)
            assert 1 <= int(likelihood) <= 4 and 1 <= int(impact) <= 4
            if f"({score})" not in screen:
                fail(errors, f"{tid}: incorrect risk screening score")
        except (ValueError, AssertionError):
            fail(errors, f"{tid}: invalid L/I scoring")
        refs = re.findall(r"KS-NET-\d{3}", contract)
        if not refs or any(ref not in requirement_ids for ref in refs):
            fail(errors, f"{tid}: absent/unknown requirement: {refs}")
        future_tests = re.findall(r"TV-\d{2}", tests)
        if not future_tests or any(ref not in test_ids for ref in future_tests):
            fail(errors, f"{tid}: absent/unknown test ID: {future_tests}")
        if not re.search(r"M\d+\.\d+", owner):
            fail(errors, f"{tid}: no roadmap owner")

    # Only inspect local links; external references are not fetched.
    for path in [ROOT / "README.md", ROOT / "PRODUCT_VISION.md", ROOT / "docs/architecture/PRODUCT_SCOPE.md", ROOT / "docs/security/SECURITY_PRINCIPLES.md", ROOT / "docs/development/RELEASE_OBJECTIVES.md", MODEL, REGISTER, MATRIX]:
        content = path.read_text(encoding="utf-8")
        for raw in re.findall(r"\]\(([^)]+)\)", content):
            url = urlparse(raw.split(" ", 1)[0])
            if url.scheme or url.netloc or raw.startswith("#"):
                continue
            local = (path.parent / unquote(url.path)).resolve()
            if not local.is_relative_to(ROOT.resolve()) or not local.is_file():
                fail(errors, f"{path.relative_to(ROOT)}: broken/unsafe local link: {raw}")

    for term in ["agentless", "compromised", "prompt-injection", "residual", "mitigation", "STRIDE"]:
        if term.lower() not in model.lower():
            fail(errors, f"Threat model missing required discussion: {term}")
    if "Not assessed" not in register or "not yet been implemented" not in matrix.lower() and "no tests listed here have yet been implemented" not in matrix.lower():
        fail(errors, "Missing explicit unverified/residual-risk status")

    return errors


if __name__ == "__main__":
    problems = verify()
    if problems:
        print("M0.3 documentation verification: FAIL", file=sys.stderr)
        for error in problems:
            print(f"  - {error}", file=sys.stderr)
        sys.exit(1)
    print("M0.3 documentation verification: PASS")
    print("  42 unique threats, 12 trust boundaries, 42 network requirements")
    print("  30 prospective verification cases, valid owners/links/ratings")
    print("  All controls and residual risks remain explicitly unverified")

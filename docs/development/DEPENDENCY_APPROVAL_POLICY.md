<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Dependency and Supply-Chain Approval Policy

**Decision:** M0.6. This defines a procedure, **not** approval to download, build or bundle any candidate dependency.

## 1. Scope and default rule

Review each package, Qt module, KDE Frameworks component, C/C++ library, CLI tool, Python module, embedded asset, detection-rule corpus, threat feed, and offline AI model artifact. Distinguish **build-only**, **test-only**, **runtime system-provided**, **linked runtime**, **bundled runtime**, **dataset**, and **model** roles. No non-trivial dependency is accepted for implementation or distribution until its intended use is reviewed in `DEPENDENCY_REGISTER.md` and the actual version/packaging is recorded.

## 2. Required approval record

| Field | Minimum evidence |
|---|---|
| Name and role | Exact upstream project/module, purpose, responsible owner |
| Version | Pinned semantic version/tag, package version or commit; Ubuntu repository identity if applicable |
| Origin | Canonical upstream URL, signed/tagged provenance where available; mirror/third-party source risks |
| Integrity | Hash of direct downloads, lockfile and artifact identity; no anonymous/unpinned fetch in release workflow |
| License | SPDX identifier(s), full licenses, exceptions, NOTICE and embedded/recursive dependencies |
| Integration | Dynamic/static, source copying, external process, system package, container/bundle; concrete distribution mode |
| Security | Vulnerability screening, maintenance state, attack surface, privilege requirements, input provenance |
| Privacy/network | Telemetry disclosure risk, update URLs, auto-download behavior, tracking, API key handling |
| Supply chain | CI provenance, reproducibility or verification strategy, SBOM ownership, update cadence |
| Decision | `CANDIDATE`, `REVIEW_REQUIRED`, `APPROVED_FOR_BUILD`, `APPROVED_FOR_DISTRIBUTION`, `REJECTED`, or `RETIRED` and review date |
| Evidence | Review notes, approved artifact list, planned tests, reviewer and dependency-graph inventory |

**Approval is scoped to a specific version, use, dependency graph and distribution path.** Build-use approval does not imply redistribution permission. Major version changes, linkage changes, newly vendored libraries, newly downloaded models and new transitive dependencies require review. A new CVE, compromised provenance or license ambiguity can revoke approval and block release.

## 3. Reproducibility and update rules

- Prefer maintained distribution packages on Ubuntu 26.04 for the first release, but record resolved package versions and provenance in released SBOMs.
- Prefer upstream signed releases or verified source commits for external dependencies; hash every downloaded archive; avoid `latest` tags.
- No uncontrolled build-time Internet downloads. If external fetches are required, make them explicit, pinned, auditable and reproducible.
- No default installation of Docker/Podman is required; use hosted CI and clean VM testing as appropriate.
- Track transitive libraries, bundled tools, codec/runtime components, interpreter plugins, QML modules and generated resources.
- Record vulnerabilities with exact affected version/configuration and remediation status; a scanner hit is a finding to triage, not automatically proof of exploitation or irrelevance.
- Preserve source and binary distribution notices for every redistributed dependency; ensure redistribution grants are actually satisfied.
- Treat network signatures, CVE feeds, commercial threat feeds, proprietary IoT MIBs and AI weights as separately governed datasets; do not infer permission from public readability.
- No arbitrary network egress may be justified solely by a dependency's default updater. KnetSentry's approved external-intelligence client and provider policy govern runtime egress.
- Reject new components with unknown authorship, unreviewable license chains or unacceptable maintenance/security posture until resolved.

## 4. Review outcomes and future gates

M1.1/M1.3: approve the **actual** CMake/Qt/KF6/Kirigami modules and Ubuntu package versions before linking. M3/M4: review network, TLS, and capture libraries. M6/M9: review SQLite, capture and gateway integrations. M10: review Sigma imports, ATT&CK feeds and provider data licenses. M12: review AI runtimes and weights independently. M13.7: whole-graph security review. M15.5: artifact-derived distribution audit and SBOM before publication.

Change-control proof: the dependency register entry, PR link, test evidence and approved version must be available to reviewers. `APPROVED_FOR_DISTRIBUTION` is only assigned after inspecting the packages actually being shipped, not inferred from an upstream description.

## 5. M0.7 build and CI verification dependency

The [secure development contract](../../DEVELOPMENT_CONTRACT.md) requires
versioned toolchain checks, permission-minimized GitHub Actions and official
REUSE verification when those jobs are introduced in M1. Approval to run a
static analyzer or Qt module is not blanket approval to redistribute it; the
version-and-artifact decisions above remain authoritative.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Project status

**Accepted baseline: M4.3 — mutually authenticated TLS.** Milestone 3 is complete
through issue #33. M4.4 adds offline explicit endpoint enrollment;
target-host qualification of this revision is pending. This is an
unreleased development baseline, not a v1.0.0 security qualification.

## Available today

| Area | Implemented behavior |
| --- | --- |
| Desktop | Seven Qt 6/Kirigami sections; global health indicator and heartbeat; owned-manager Play/Stop and cleanup; Dashboard health and read-only Settings scope |
| Manager | Non-root lifecycle, strict lifecycle-only v1 configuration, opt-in same-UID/GID authenticated Unix IPC (`STATUS`, `HEALTH`), bounded health and protected audit logging |
| Deployment | Explicit development systemd deployment under a dedicated non-login identity with confinement; ordinary desktop IPC remains separate |
| Network security | Default-deny preflight, strict IPv4/IPv6 prefixes and interface binding, Linux effective/FIB route checks, sticky authorization invalidation, optional dedicated-UID deny-all nftables profile |
| Agent protocol | KSAP 1.0 bounded HELLO/HEARTBEAT codec and connection-local ordering; no operational transport or enrollment |
| Cryptographic identity | Offline Ed25519 key generation, protected role-specific storage and explicit X.509 trust/role/pin validation; no issuance or enrollment |
| TLS transport | TLS 1.3 mutual identity, explicit root and role/pin validation, bounded encrypted byte stream; no operational socket adapter |
| Endpoint enrollment | Offline administrative registry and TLS-backed admission; no production integration or automatic enrollment |
| Verification | Mandatory compiled regressions, static analysis, sanitizer configurations, strict QML diagnostics, isolated dual-stack kernel firewall and topology fixtures |

The policy engine does not grant operational transport authority. The manager
does not publish active network approvals or network denial events. Local IPC
rejection counters are not network incidents. The production firewall profile
is not installed automatically; test-only positive permissions are not deployment
rules. Monitoring is unavailable, and no agent, sensor, event database, detection,
incident workflow, public feed client or AI inference is operational.

## Accepted verification snapshot

The maintainer's M3.8 acceptance run (2026-11-25 UTC, applied working tree
based on `635c14b`) reported 77 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED.
The maintainer subsequently reported manual GUI acceptance and merge after
nine green hosted checks for the M3.8 implementation (`120840f`).

| Configuration | Passing CTests |
| --- | ---: |
| Release / Debug / Clazy / clang-tidy (each) | 38/38 |
| Full ASan/UBSan | 33/33 |
| Core-only Release | 26/26 |
| Core-only ASan/UBSan | 27/27 |

The subsequent documentation refresh reported 78 PASS, 0 FAIL, 0 SKIPPED,
0 BLOCKED and nine green hosted checks (`35574f2`); no application changes.

The M4.1 maintainer acceptance (2026-11-25 UTC, working tree based on
`35574f2`) reported 81 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, with 39/34
desktop and 27/28 core-only CTests (normal/sanitized), 36 structural verifiers,
and nine green hosted checks (`c1f5d0b`); manual GUI checks and merge were
reported successful.

The M4.2 maintainer acceptance (2026-11-25 UTC, corrected working tree based
on `43a4697`) reported 84 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, desktop 40/35
and core-only 28/29 CTests (normal/sanitized), matching OpenSSL 3.5.5 headers
and runtime, and nine green hosted checks (`79072f9`). The maintainer reported
manual GUI verification and merge.

The M4.3 maintainer acceptance (2026-11-25 UTC, working tree based on
`79072f9`) reported 86 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, desktop 41/36
and core-only 29/30 CTests (normal/sanitized), matching OpenSSL 3.5.5 headers
and runtime, and nine green hosted checks (`e2a9018`). The maintainer reported
manual GUI verification and merge.

The earlier M3.8 run included 34 structural verifiers; official REUSE, strict QML checks, installed systemd,
and the isolated M3.5–M3.7 live regressions passed. This snapshot is historical
evidence, not an assertion about any subsequent revision or environment.
No independent audit, release artifact qualification or comprehensive threat
closure is claimed. See the [toolchain matrix](development/TOOLCHAIN_TEST_MATRIX.md)
and [evidence guide](development/VERIFICATION_EVIDENCE.md).

## Development roadmap

| Stage | Status |
| --- | --- |
| M0 — requirements, threat model, architecture and governance | Complete |
| M1 — C++/Qt foundation, testing and CI | Complete |
| M2 — manager, IPC, audit, health, systemd and desktop lifecycle | Complete |
| M3 — LAN scope policy, firewall, isolated tests and GUI inspection | Complete through M3.8 |
| M4 — identity, PKI and secure agent enrollment | M4.3 accepted; M4.4 implementation, qualification pending |
| M5–M7 — functional SIEM foundations | Planned |
| M8–M12 — advanced security operations | Planned |
| M13–M15 — qualification, packaging and v1.0.0 | Planned |
| M16 — possible KDE community adoption | Post-v1.0 aspiration |

[GitHub milestones](https://github.com/SpilledMilkFactory/KnetSentry/milestones)
are the live issue-tracking authority. See [release objectives](development/RELEASE_OBJECTIVES.md)
for the detailed release bar and [documentation index](README.md) for the technical
contracts. No future issue is marked accepted by this roadmap.

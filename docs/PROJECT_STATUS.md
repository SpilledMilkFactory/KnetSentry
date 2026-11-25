<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Project status

**Accepted baseline: M3.8 — LAN scope inspection.** Milestone 3 is complete
through issue #33. M4.1 introduces an offline agent wire contract; target-host
qualification of this revision is pending. This is an
unreleased development baseline, not a v1.0.0 security qualification.

## Available today

| Area | Implemented behavior |
| --- | --- |
| Desktop | Seven Qt 6/Kirigami sections; global health indicator and heartbeat; owned-manager Play/Stop and cleanup; Dashboard health and read-only Settings scope |
| Manager | Non-root lifecycle, strict lifecycle-only v1 configuration, opt-in same-UID/GID authenticated Unix IPC (`STATUS`, `HEALTH`), bounded health and protected audit logging |
| Deployment | Explicit development systemd deployment under a dedicated non-login identity with confinement; ordinary desktop IPC remains separate |
| Network security | Default-deny preflight, strict IPv4/IPv6 prefixes and interface binding, Linux effective/FIB route checks, sticky authorization invalidation, optional dedicated-UID deny-all nftables profile |
| Agent protocol | KSAP 1.0 bounded HELLO/HEARTBEAT codec and connection-local ordering; no transport or enrollment |
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

34 structural verifiers, official REUSE, strict QML checks, installed systemd,
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
| M4 — identity, PKI and secure agent enrollment | M4.1 implementation; qualification pending |
| M5–M7 — functional SIEM foundations | Planned |
| M8–M12 — advanced security operations | Planned |
| M13–M15 — qualification, packaging and v1.0.0 | Planned |
| M16 — possible KDE community adoption | Post-v1.0 aspiration |

[GitHub milestones](https://github.com/SpilledMilkFactory/KnetSentry/milestones)
are the live issue-tracking authority. See [release objectives](development/RELEASE_OBJECTIVES.md)
for the detailed release bar and [documentation index](README.md) for the technical
contracts. No future issue is marked accepted by this roadmap.

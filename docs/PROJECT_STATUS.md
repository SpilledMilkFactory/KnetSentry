<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Project status

**Accepted baseline: M5.6 — initial local file integrity monitoring.**
Milestones 0–3 are complete. M4.7's implemented read-only scope is qualified and
merged; issue #40's remaining operational GUI capabilities remain outstanding.
M4.8 and M5.1–M5.6 are merged (M5.5 offline foundation only). M5.7 adds
mandatory explicit active-collector privacy policy, acquisition-time redaction
and policy-bound journal state; target qualification is pending.
Issue #46 operational network/manager integration remains outstanding.
This is an unreleased development baseline, not a v1.0.0 security qualification.

## Available today

| Area | Implemented behavior |
| --- | --- |
| Desktop | Seven Qt 6/Kirigami sections; global health indicator and heartbeat; owned-manager Play/Stop and cleanup; Dashboard health, read-only Settings scope and Assets enrollment roster |
| Manager | Non-root lifecycle, strict lifecycle-only v1 configuration, opt-in same-UID/GID authenticated Unix IPC (`STATUS`, `HEALTH`, `AGENTS`), bounded health and protected audit logging |
| Deployment | Explicit development systemd deployment under a dedicated non-login identity with confinement; ordinary desktop IPC remains separate |
| Network security | Default-deny preflight, strict IPv4/IPv6 prefixes and interface binding, Linux effective/FIB route checks, sticky authorization invalidation, optional dedicated-UID deny-all nftables profile |
| Agent protocol | KSAP 1.0 bounded HELLO/HEARTBEAT codec and separate KSTD 1.0 bounded offline telemetry/ACK exchange; no operational transport |
| Cryptographic identity | Offline Ed25519 key generation, protected role-specific storage and explicit X.509 trust/role/pin validation; no issuance or enrollment |
| TLS transport | TLS 1.3 mutual identity, explicit root and role/pin validation, bounded encrypted byte stream; no operational socket adapter |
| Endpoint enrollment | Offline registry, TLS-backed admission, explicit rotation/revocation and live validity rechecks; explicit local read-only roster selection; no operational admission or automatic enrollment |
| Endpoint agent | Independent foreground process, strict v1 startup configuration, bounded static collector lifecycle and non-root capability checks; opt-in selected journal metadata, authentication categories and journal-mediated audit records and explicit file integrity polling under mandatory explicit privacy policy; no operational network |
| Telemetry delivery | Explicit protected FIFO outbox, durable bounded inbox and authenticated receipt/retry contract (offline); no running manager receiver |
| Agent health | Offline TLS-backed KSAP reporting, current enrollment rechecks, bounded health snapshots and reconnect scheduling; no deployed agent |
| Verification | Mandatory compiled regressions, static analysis, sanitizer configurations, strict QML diagnostics, isolated dual-stack kernel firewall and topology fixtures |

The policy engine does not grant operational transport authority. The manager
does not publish active network approvals or network denial events. Local IPC
rejection counters are not network incidents. The production firewall profile
is not installed automatically; test-only positive permissions are not deployment
rules. Monitoring is unavailable, and no operational remote telemetry transport, sensor, event database, detection,
incident workflow, public feed client or AI inference is operational.

## Accepted verification snapshot

M5.6 maintainer acceptance (2026-11-26 UTC, applied working tree based on
`b4e787f`) recorded 109 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 357 CTest
executions, 49 structural verifiers and nine green hosted checks (`06fb6d8`).
Focused seven-test run and installed-manager binary comparison passed. Manual
FIM verified content and metadata changes, replacement, deletion, creation,
independent slots, no observation for unrelated sibling changes, startup and
runtime symbolic-link rejection, wildcard rejection and clean shutdown. The
maintainer reported GUI functionality and merge. The Kirigami drawer and
portal application-ID warnings recurred; neither is marked resolved.

M5.5 maintainer acceptance (2026-11-25 UTC, applied working tree based on
`ca888d5`) recorded 107 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, 350 CTest executions,
48 structural verifiers and nine green hosted checks (`b4e787f`). Manual
restart retained 63 queued records with destination binding, unique cursors
and checkpoint consistency. Invalid binding and destination substitution
were rejected; focused authenticated delivery passed. Maintainer reported GUI
verification and merge. Kirigami drawer bottomMargin binding-loop and portal
application-ID warnings recurred and remain unresolved. Issue #46 operational
agent-to-manager delivery is still outstanding.

M5.4 maintainer acceptance (2026-11-25 UTC, applied working tree based on
`a6802ec`) recorded 105 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, 343 CTest executions,
47 structural verifiers and nine green hosted checks (`ca888d5`). Maintainer
reported manual GUI verification and merge. No live audit-mode terminal
record count or unavailable-source demonstration was supplied; only synthetic
native positive/negative audit coverage is independently evidenced by the log.
Previously documented desktop diagnostics are not marked resolved.

M5.3 maintainer acceptance (2026-11-25 UTC, applied working tree based on
`010b788`) recorded 103 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, 336 CTest executions,
46 structural verifiers and nine green hosted checks (`a6802ec`). Live collection
retained 63 records (14 recognized session removals, 49 unclassified), validated
permissions and metadata structure, and retained 63 unique cursors after restart.
Unsupported source, wildcard and missing directory were rejected. The maintainer
reported manual GUI functionality and merge; the previously reported desktop
diagnostics remain unresolved (no new diagnostic evidence supplied).


M5.2 maintainer acceptance (2026-11-25 UTC, applied working tree based on
`b25cf83`) recorded 101 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, 329 CTest executions,
45 structural verifiers, libsystemd-dev 259.9-0ubuntu0.1, and nine green hosted
checks (`010b788`). Live verification retained 54 records, verified timestamps
and provenance, and retained 54 unique cursors after restart. Invalid wildcard
and missing-directory configurations were rejected. The maintainer reported
merge and manual GUI functionality; manual output contained a Kirigami drawer
bottomMargin binding loop and desktop portal app-ID registration warning.
These remain unresolved desktop diagnostics, not journal qualification failures.


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

The M4.4 maintainer acceptance (2026-11-25 UTC, working tree based on
`e2a9018`) reported 88 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, desktop 43/38
and core-only 31/32 CTests (normal/sanitized), and nine green hosted checks
(`8dc778f`). The maintainer reported manual GUI and offline administrative
verification and merge.

The M4.5 maintainer acceptance (2026-11-25 UTC, working tree based on
`8dc778f`) reported 90 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, desktop 44/39
and core-only 32/33 CTests (normal/sanitized), matching OpenSSL 3.5.5 headers
and runtime, and nine green hosted checks (`a1cf0b0`). The maintainer reported
manual GUI verification and merge.

The M4.6 maintainer acceptance (2026-11-25 UTC, working tree based on
`a1cf0b0`) reported 92 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, desktop 45/40
and core-only 33/34 CTests (normal/sanitized), and nine green hosted checks
(`779e8a5`). The maintainer reported manual GUI verification and merge.

The M4.7 follow-up maintainer acceptance (2026-11-25 UTC, working tree
based on `931bd1b` with the follow-up changes) reported 94 PASS, 0 FAIL,
0 SKIPPED, 0 BLOCKED, desktop 47/42 and core-only 35/36 CTests
(normal/sanitized), strict QML and installed systemd success. The maintainer
reported manual GUI verification and merge after nine green hosted checks
(`8634c76`). This accepts only the implemented read-only foundation.

The M4.8 maintainer acceptance (2026-11-25 UTC, working tree based on
`8634c76` with M4.8 changes) reported 96 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED,
desktop 48/43 and core-only 36/37 CTests (normal/sanitized), 43 structural
verifiers, strict QML, installed systemd and isolated network checks. The
maintainer reported manual GUI verification and merge after nine green hosted
checks (`79c7a49`). This is composed library-level authentication evidence,
not operational socket or release qualification.

The M5.1 follow-up maintainer acceptance (2026-11-25 UTC, working tree
based on `e98a7b5` with the corrective changes) reported 98 PASS, 0 FAIL,
0 SKIPPED, 0 BLOCKED and all 322 CTest executions (50/45 desktop, 38/39
core-only, normal/sanitized). The caller had inheritable-only capabilities;
removal with unchanged caller passed. The maintainer reported independent
foreground execution, clean Ctrl+C exit, rejection of invalid configuration,
manual GUI verification and merge following nine green checks (`b25cf83`).
The initial 87 PASS, 8 FAIL, 3 SKIPPED, 0 BLOCKED run is superseded, not erased.

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
| M4 — identity, PKI and secure agent enrollment | M4.8 accepted; issue #40 remaining capabilities open |
| M5–M7 — functional SIEM foundations | M5.6 accepted; M5.7 qualification pending; operational delivery outstanding |
| M8–M12 — advanced security operations | Planned |
| M13–M15 — qualification, packaging and v1.0.0 | Planned |
| M16 — possible KDE community adoption | Post-v1.0 aspiration |

[GitHub milestones](https://github.com/SpilledMilkFactory/KnetSentry/milestones)
are the live issue-tracking authority. See [release objectives](development/RELEASE_OBJECTIVES.md)
for the detailed release bar and [documentation index](README.md) for the technical
contracts. No future issue is marked accepted by this roadmap.

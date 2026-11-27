<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Project status

**Accepted baseline: M7.2 — Detection-rule schema and validation.**
Milestones 0–3 are complete. M4.7's implemented read-only scope is qualified and
merged; issue #40's remaining operational GUI capabilities remain outstanding.
M4.8 and M5.1–M5.8 are merged (M5.5 offline foundation only). M5.9 local aggregate agent status in Dashboard and Assets is qualified and merged. Multi-endpoint authenticated status integration remains outstanding (#50).
Issue #46 operational network/manager integration remains outstanding.
M6.1 bounded offline authenticated event ingestion is qualified and merged; operational and generic envelope integration (#51) remain outstanding.
M6.2 typed OCSF-aligned normalization of the KSTD subset is qualified and merged.
M6.3–M6.8 storage, integrity, search, quotas, explicit cleanup and opt-in manager-mediated stored event exploration foundations are qualified and merged. M6.9 composed failure-recovery regressions are qualified and merged. M6.10 independently approved split-storage foundation is qualified and merged, including actual mount replacement and distinct local filesystem tests. Persistent cross-boot approval and operational integration remain outstanding (#148).
M7.1 bounded offline deterministic rule evaluation is qualified and merged. M7.2 versioned rule schema and validation are qualified and merged. M7.3 adds bounded offline authentication-pattern detection; target qualification pending. No operational detection, alert persistence or response authority is enabled.
This is an unreleased development baseline, not a v1.0.0 security qualification.

## Available today

| Area | Implemented behavior |
| --- | --- |
| Desktop | Seven Qt 6/Kirigami sections; global health indicator and heartbeat; owned-manager Play/Stop and cleanup; Dashboard health, read-only Settings scope and Assets enrollment roster; explicit local agent status in Dashboard/Assets; bounded stored event exploration through an explicitly selected foreground manager |
| Manager | Non-root lifecycle, strict lifecycle-only v1 configuration, opt-in same-UID/GID authenticated Unix IPC (`STATUS`, `HEALTH`, `AGENTS`, opt-in audited `EVENTS`), bounded health and protected audit logging |
| Deployment | Explicit development systemd deployment under a dedicated non-login identity with confinement; ordinary desktop IPC remains separate |
| Network security | Default-deny preflight, strict IPv4/IPv6 prefixes and interface binding, Linux effective/FIB route checks, sticky authorization invalidation, optional dedicated-UID deny-all nftables profile |
| Agent protocol | KSAP 1.0 bounded HELLO/HEARTBEAT codec and separate KSTD 1.0 bounded offline telemetry/ACK exchange; no operational transport |
| Cryptographic identity | Offline Ed25519 key generation, protected role-specific storage and explicit X.509 trust/role/pin validation; no issuance or enrollment |
| TLS transport | TLS 1.3 mutual identity, explicit root and role/pin validation, bounded encrypted byte stream; no operational socket adapter |
| Endpoint enrollment | Offline registry, TLS-backed admission, explicit rotation/revocation and live validity rechecks; explicit local read-only roster selection; no operational admission or automatic enrollment |
| Endpoint agent | Independent foreground process, strict v1 startup configuration, bounded static collector lifecycle and non-root capability checks; opt-in selected journal metadata, authentication categories and journal-mediated audit records and explicit file integrity polling under mandatory explicit privacy policy; no operational network |
| Event ingestion | Bounded per-source authenticated KSTD receipt pipeline, canonical validation, reject/overload disposition counters; no deployed manager ingress |
| Event normalization | OCSF 1.4.0-aligned internal projection, native provenance, explicit mapping disposition and post-commit typed result; no normalized persistence or OCSF export |
| Event storage | Database-independent storage interface, volatile reference and transactional SQLite development backend with record integrity commitments and typed bounded search; opt-in read-only inspection of existing development stores; no operational persistence or ACK integration |
| Telemetry delivery | Explicit protected FIFO outbox, durable bounded inbox and authenticated receipt/retry contract (offline); no running manager receiver |
| Agent health | Offline TLS-backed KSAP reporting, current enrollment rechecks, bounded health snapshots and reconnect scheduling; no deployed agent |
| Verification | Mandatory compiled regressions, static analysis, sanitizer configurations, strict QML diagnostics, isolated dual-stack kernel firewall and topology fixtures |

The policy engine does not grant operational transport authority. The manager
does not publish active network approvals or network denial events. Local IPC
rejection counters are not network incidents. The production firewall profile
is not installed automatically; test-only positive permissions are not deployment
rules. Monitoring is unavailable, and no operational remote telemetry transport, sensor, production event database, detection,
incident workflow, public feed client or AI inference is operational.

## Accepted verification snapshot

M7.2 maintainer acceptance (2026-11-27 UTC, applied working tree based on `a71d775`) recorded 141 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 491 configured CTests, 64 structural verifiers, 70 repeated Release and 35 repeated sanitized executions, clean Release/analysis diagnostic inspection, installed manager equality, GUI independence, and nine green hosted checks (`d780fd7`). Manual GUI review and merge were reported successful.

M7.1 maintainer acceptance (2026-11-27 UTC, applied working tree based on `bd03c2c` with the two corrective files modified) recorded 139 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 484 configured CTest executions, 63 structural verifiers, 60 repeated Release and 30 repeated sanitized executions, clean Release/analysis-build diagnostics, GUI independence, installed manager equality, actual private mount regression and nine green hosted checks (`a71d775`). Manual GUI regression and merge were reported successful.

M6.10 maintainer acceptance (2026-11-27 UTC, applied working tree based on `5518bef`) recorded 137 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 477 configured CTest executions, 62 structural verifiers, 140 repeated Release and 70 repeated sanitized executions, zero warning/error diagnostics in the analysis build section and nine green hosted checks (`148a5d9`). Actual private bind mount detachment/replacement and independent local filesystem persistence/restart passed. Synthetic raw and index files had mode 0600. Manual GUI regression and merge were reported successful. Cross-boot UUID authorization and operational integration remain outstanding (#148).

M6.9 maintainer acceptance (2026-11-27 UTC, applied working tree based on `87a5c87`) recorded 134 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 470 configured CTest executions, 61 structural verifiers, 130 repeated Release and 65 repeated sanitized executions, zero warning/error diagnostics in the analysis build section, and nine green hosted checks (`5518bef`). Direct recovery, authenticated ingestion and preceding transport checks passed; manual GUI review and merge were reported successful.

M6.8 maintainer acceptance (2026-11-27 UTC, applied working tree based on
`10359f9`) recorded 132 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 456 configured
CTest executions, 60 structural verifiers and nine green hosted checks
(`87a5c87`). Native explorer, persistent SQLite manager, rendered GUI,
nine prior storage/security tests, 110 repeated Release and 55 repeated sanitized
executions passed. Analysis-build inspection found no warning/error diagnostics.
Manual screenshots demonstrate ascending pages 1–8, 9–16, 17–20,
filtered descending failures, selected normalized event details and disabled
next-page controls at the end. Remaining GUI tests and merge were reported
successful. Operational receipt-to-store integration, production roles and
storage-volume authorization remain outstanding.

M6.7 maintainer acceptance (2026-11-27 UTC, applied working tree based on
`265058e`) recorded 130 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 438 configured
CTest executions, 59 structural verifiers and nine green hosted checks
(`10359f9`). Focused Release 12/12, analysis 6/6, 90 repeated Release and 45
repeated sanitized executions passed; a further captured sanitized rerun
also passed 45/45. Direct storage, integrity, normalization and receipt
regressions passed. Analysis diagnostics, installed manager byte comparison,
independent agent lifecycle and reported GUI review and merge passed.
Production volume quotas and retention authorization remain open.

M6.6 maintainer acceptance (2026-11-27 UTC, applied working tree based on
`ad603ef`) recorded 128 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 431 configured
CTest executions, 58 structural verifiers and nine green hosted checks
(`265058e`). Focused Release 11/11, analysis 5/5, 80 repeated Release executions,
and direct search, integrity, storage and receipt tests passed. The supplementary
sanitized transcript ends during the last search repetitions (37 completed
successful executions visible); consolidated sanitizer suites passed. Analysis
log inspection found no warning/error diagnostics. GUI review and merge were
reported successful. Operational query authorization and production placement remain open.

M6.5 maintainer acceptance (2026-11-27 UTC, applied working tree based on
`1f9f538`) recorded 126 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 424 CTest
executions, 57 structural verifiers and nine green hosted checks (`ad603ef`).
Focused Release 10/10 and analysis 3/3, 70 repeated Release executions and
direct integrity and prior storage/receipt regressions passed. The supplementary
sanitized transcript ends mid-run (32 completed successful executions visible);
the consolidated sanitizer suites passed. Analysis log inspection found no
warning/error diagnostics. GUI review and merge were reported successful. Independent integrity trust anchors and operational
storage integration remain open.

M6.4 maintainer acceptance (2026-11-27 UTC, applied working tree based on
`0822ed2`) recorded 124 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 417 CTest
executions and nine green hosted checks (`1f9f538`). SQLite 3.46.1, focused
analysis 2/2 and Release 9/9, 60 repeated Release and 30 repeated sanitized
executions, installed manager comparison and agent lifecycle passed. Analysis
log inspection found no warning/error diagnostics. GUI review and merge were
reported successful. Production placement and manager integration remain open.

M6.3 maintainer acceptance (2026-11-26 UTC, applied working tree based on
`77304f7`) recorded 121 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 410 configured
CTest executions and nine green hosted checks (`0822ed2`). Eight focused tests,
50 repeated Release and 25 repeated sanitized executions, manager comparison,
independent agent lifecycle, GUI review and merge were successful. The analysis
build emitted an EnumCastOutOfRange warning from the deliberate invalid-mode
cast in the M6.2 test; M6.4 replaces that cast with checked decoding and promotes
Clang analyzer diagnostics to errors. Corrected Ubuntu qualification passed during M6.4.


M6.2 maintainer acceptance (2026-11-26 UTC, applied working tree based on
`f70966f`) recorded 119 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 403 CTest
executions, 54 structural verifiers and nine green hosted checks (`77304f7`).
Focused seven-test verification, direct normalization/ingestion/delivery,
40 repeated Release and 20 repeated sanitized executions, installed manager
comparison and independent agent lifecycle passed. Maintainer reported GUI
qualification and merge. Operational issues #40/#46/#50/#51 remain outstanding.

M6.1 maintainer acceptance (2026-11-26 UTC, applied working tree based on
`11149c3`) recorded 117 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 396 CTest
executions, 53 structural verifiers and nine green hosted checks (`f70966f`).
Direct ingestion and delivery tests exited 0; 30 repeated Release and 15 repeated
sanitized ingestion/delivery/recovery executions passed. Independent agent
lifecycle exited 0. Maintainer reported visual qualification and merge.
Operational issues #40/#46/#50/#51 remain outstanding.

M5.9 maintainer acceptance (2026-11-26 UTC, applied working tree based on
`d6677a5`) recorded 115 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 389 CTest
executions, 52 structural verifiers and nine green hosted checks (`11149c3`).
Focused seven-test Release run, strict QML lint and installed-manager comparison
passed. Manual metadata-only FIM observed a change, suspension/resumption was
exercised, unsafe substitution exited 1, and buffered authentication stopped
with exit 0. Maintainer reported visual qualification and merge; no exact
manual queue occupancy or rate was recorded. Existing desktop diagnostics and
operational issues #40/#46/#50 remain outstanding.

M5.8 corrected maintainer acceptance (2026-11-26 UTC, applied working tree
based on `743dd54`) recorded 113 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all
371 CTest executions, 51 structural verifiers and nine green hosted checks
(`d6677a5`). The Clazy correction passed. Direct recovery execution exited 0;
20 repeated Release and 10 repeated sanitized recovery/delivery executions
passed. Installed-manager binary comparison passed. Maintainer reported GUI
verification and merge. Issues #40/#46 and prior desktop diagnostics remain open.

M5.7 maintainer acceptance (2026-11-26 UTC, applied working tree based on
`06fb6d8`) recorded 111 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, 364 CTest
executions, 50 structural verifiers and nine green hosted checks (`420215f`).
Focused eight-test run and installed-manager binary comparison passed. Manual
metadata-only and full FIM, missing/denied/conflicting policy rejection, and
redacted restart retaining 63 unique records were demonstrated. Changed-policy
startup returned exit 1 without mutating the outbox. Maintainer reported GUI
verification and merge. Previously documented desktop warnings remain unresolved.

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
| M5–M7 — functional SIEM foundations | M7.2 accepted; M7.3 qualification pending; persistent volume approval and operational integration outstanding |
| M8–M12 — advanced security operations | Planned |
| M13–M15 — qualification, packaging and v1.0.0 | Planned |
| M16 — possible KDE community adoption | Post-v1.0 aspiration |

[GitHub milestones](https://github.com/SpilledMilkFactory/KnetSentry/milestones)
are the live issue-tracking authority. See [release objectives](development/RELEASE_OBJECTIVES.md)
for the detailed release bar and [documentation index](README.md) for the technical
contracts. No future issue is marked accepted by this roadmap.

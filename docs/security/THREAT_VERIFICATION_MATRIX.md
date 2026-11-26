<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Threat Verification and Ownership Matrix

**Issue:** M0.3 / GitHub #3
**Status:** Original M0.3 test specifications retained; at that baseline,
no tests listed here have yet been implemented or executed. As of M3.8,
selected subsets are implemented and qualified (see progress below).
**Threat source:** [THREAT_MODEL.md](THREAT_MODEL.md) and
[THREAT_REGISTER.md](THREAT_REGISTER.md).
**Existing network-specific cases:** [NETWORK_SCOPE_VERIFICATION_PLAN.md](NETWORK_SCOPE_VERIFICATION_PLAN.md).

## Verification method and acceptance evidence

Tests should run against deterministic fixtures or isolated test networks;
never probe unrelated Internet systems or alter the developer's normal
firewall. Future security reviews must record environment, threat IDs,
requirement IDs, expected/observed outcomes, regressions, and any uncovered
limitations. A passing unit test is not sufficient evidence for a Linux
host-enforcement claim; systemd/nftables effectiveness needs integration
verification on Ubuntu 26.04. Real agentless capture acceptance requires
actual visibility from a supported sensor/source, not an invented flow.

The `TV-##` IDs are verification work items, not GitHub issue numbers.

**M3.8 progress:** TV-08 has partial evidence from [local IPC lifecycle tests](../development/SERVICE_LIFECYCLE_IPC_M28.md)
and [desktop scope inspection](../development/DESKTOP_NETWORK_SCOPE_M38.md).
TV-09 has partial evidence from [fail-closed authorization](../development/NETWORK_AUTHORIZATION_M34.md),
[firewall](../development/FIREWALL_ENFORCEMENT_M35.md) and [adversarial tests](../development/NETWORK_ADVERSARIAL_M37.md).
These do not qualify a privileged administrative API, operational transport,
monitoring, or deployed end-to-end enforcement. TV-27 has partial confinement
evidence from [systemd](../development/SYSTEMD_SERVICE_M27.md). No TV item is
closed by this refresh; see [accepted baseline](../PROJECT_STATUS.md).

**M4.1 implementation:** [KSAP 1.0](../development/AGENT_PROTOCOL_M41.md) adds
offline framing and connection-local sequence regression coverage for TV-07.
M4.1 target acceptance passed; cross-connection replay and authenticated ingestion
remain unqualified. No threat is closed.

**M4.2 implementation:** [identity contract](../development/IDENTITY_M42.md)
adds partial TV-06 evidence for protected key storage, explicit trust roots,
certificate purpose, validity and pinned public-key identity. Target M4.2 acceptance passed. Issuance, enrollment, rotation and revocation
remain required. No threat is closed.

**M4.3 implementation:** [mutual TLS](../development/TLS_TRANSPORT_M43.md) adds
partial TV-06 proof-of-possession and invalid-peer handshake evidence;
operational network binding and enrollment/revocation remain unqualified.
Target M4.3 acceptance passed.

**M4.4 implementation:** [explicit enrollment](../development/ENDPOINT_ENROLLMENT_M44.md)
adds partial TV-01/TV-06 evidence for administrator-approved unique ID/pin
bindings and TLS-backed admission. Unknown or mismatched endpoints deny;
passive discovery cannot create approvals. Production RBAC, revocation and
network integration remain unqualified. No threat is closed.

**M4.5 implementation:** [credential lifecycle](../development/CREDENTIAL_LIFECYCLE_M45.md)
adds partial TV-06 evidence for persistent retired pins, explicit rotation and
revocation, established-session expiry and terminal admission revalidation.
Production issuer, trusted time, manager trust distribution and operational
session invalidation remain unqualified. No threat is closed.

**M4.6 implementation:** [agent heartbeat and health](../development/AGENT_HEALTH_M46.md)
adds partial TV-06/TV-07/TV-13 evidence for authenticated reports, bounded framing,
current enrollment, missing/degraded health and retry scheduling. No threat is closed.

| Test ID | Expected observable security outcome | Planned owner | Proposed evidence |
| --- | --- | --- | --- |
| `TV-01` | Approved segment supports agentless observation; unapproved interface/payload retention denied; passive discovery never grants management | M3.1 / M5.10 | Approved/denied scope fixture, consent and permission logs |
| `TV-02` | Spoofed/reassigned local IDs stay uncertain; non-mirrored switch and dropped data produce incomplete coverage state | M5.10 / M9.2 / M9.6 | DHCP/IP/MAC change fixtures, loss counters, coverage screenshot |
| `TV-03` | Forged/unauthorized gateway, DHCP, syslog and export records cannot inherit trusted identities | M5.10 / M9.4 | Spoofed source fixtures and source trust labels |
| `TV-04` | Crafted packets and device-export inputs cannot trigger unchecked access, crash or unbounded parse | M5.10 / M13.3 | Fuzz seed corpus, sanitizer results, parser limits |
| `TV-05` | Floods result in bounded queues/CPU/disk and explicit loss/backpressure reporting | M6.1 / M14.3 | Rate-driven load test and queue metrics |
| `TV-06` | Bad/stolen/revoked certs, rogue enrollment and wrong identities do not acquire trusted agent rights | M4.2–M4.8 | Controlled PKI/enrollment negative tests and revocation record |
| `TV-07` | Replay, reordered, duplicated and malformed agent messages are rejected or safely deduplicated | M4.1 / M4.8 | Protocol transaction corpus and sequence assertions |
| `TV-08` | Unauthorized local IPC peers cannot read or modify sensitive manager resources | M2.3 / M2.8 | Unix peer identity/role negative tests |
| `TV-09` | Invalid policy, hostile data, route changes and firewall changes fail closed for affected operations | M3.1–M3.7 | Isolated namespace route/firewall and rollback evidence |
| `TV-10` | Malformed timestamps, types, encodings and injections are rejected/annotated without corrupting trusted event state | M6.1–M6.9 | Schema and timestamp fixtures, fuzz/sanitizer results |
| `TV-11` | Evidence changes, unauthorized incident edits and audit gaps are detectable and appropriately attributed | M6.5 / M11.2 / M11.8 | Integrity checks, audit regression, tamper fixtures |
| `TV-12` | Rule changes and suppression require authorization; poisoned events do not silently erase detection evidence | M7.5 / M7.8 / M10.8 | Positive/negative fixtures and rule audit trails |
| `TV-13` | Dropped frames, failed exports, disabled sources and overload are surfaced as degraded visibility | M5.10 / M14.3 | Sensor impairment test, health telemetry and UI state |
| `TV-14` | DNS rebinding, unapproved redirect/proxy, TLS error and internal IP targets cannot bypass provider restriction | M3.9 | Local mock HTTPS/DNS; egress capture and deny logs |
| `TV-15` | Oversized/malicious/stale feeds cannot corrupt storage or present stale indicators as fresh | M10.9 / M13.3 | Provider fixtures, validation and cache-version tests |
| `TV-16` | External sync is opt-in and never uploads raw private telemetry; queried indicator disclosure is explained | M3.9 / M10.9 | Outbound capture, privacy settings, request audit |
| `TV-17` | Hostile log content cannot cause AI privileged operations or unaudited evidence claims | M12.6 / M12.9 | Prompt-injection corpus, tool authorization denials |
| `TV-18` | Untrusted model files do not execute outside restricted, approved model interface | M12.2 / M12.3 | Malformed model fixtures, provenance and isolation test |
| `TV-19` | AI worker remains offline and within resource/IPC budgets under hostile inputs | M12.2 / M12.9 | OS network denial test, resource cap and fault injection |
| `TV-20` | Response disabled by default; false alert never triggers action absent independently approved scope | M11.5 | Authorization negative tests and response audit |
| `TV-21` | Exports obey authorization, redaction and path handling rules | M11.6 / M11.8 | Sensitive fixture, unauthorized export denial |
| `TV-22` | OUI/IP-only device cannot be assigned confirmed firmware or CVE applicability | M9.2 / M10.9 | Ambiguous asset/firmware and CVE matching fixtures |
| `TV-23` | Passive collection never scans; separately enabled local discovery is rate/scope bounded | M3.1 / M9.5 | Packet capture of passive and authorized active tests |
| `TV-24` | Third-party dependency/CI/package inputs are inventoried and verified against accepted provenance | M0.6 / M13.7 / M15.5 | Dependency locks, SBOM, build/release evidence |
| `TV-25` | Secrets are redacted from logs, traces and diagnostics | M1.6 / M13.1 | Secret marker fixtures and CI artifact inspection |
| `TV-26` | Disk-full, quota, retention and recovery behavior is bounded and visible | M6.7 / M14.4 | Filesystem capacity/fault tests and recovery logs |
| `TV-27` | GUI/capture/manager permissions prevent unintended privilege escalation | M2.7 / M13.6 | Service capability/unit inspection, adversarial checks |
| `TV-28` | Administrative IPC never binds publicly or exposes remote management endpoints | M2.3 / M3.5 | Socket/listener inspection and namespace network tests |
| `TV-29` | Lost administrator sessions cannot silently expand source approvals or access controls | M2.3 / M11.1 | Authentication/authorization and audit tests |
| `TV-30` | Interrupted migrations preserve consistency and support tested recovery | M6.4 / M14.4 | Transaction rollback and restore fixtures |

## Traceability and lifecycle rules

1. **M0.3:** The threat model, register, and this matrix are complete only when
   every threat ID maps to a proposed mitigation, requirement, owner, and test.
2. **M0.4 (design complete):** The [architecture traceability index](../architecture/ARCHITECTURE_TRACEABILITY.md)
   maps `TB-01`–`TB-12` and `TH-001`–`TH-042` to proposed component and
   interface ownership, including data origin, parser isolation, and egress.
   Deployment and control-effectiveness verification remain future work.
3. **M3–M7:** Build the network, identity, ingestion, agentless, and detection
   tests, recording CI or controlled laboratory evidence. The roadmap's
   additional `M3.9`, `M5.10`, `M7.10` and `M10.9` issues are proposed IDs
   until confirmed in GitHub.
4. **M9–M12:** Expand asset provenance, uncertainty, response safety, and
   optional AI risks as new interfaces are delivered.
5. **M13–M15:** Reassess likelihood and impact after actual controls exist;
   record any residual risk rationale and block release on unresolved
   release-blocking findings.

No missing sensor data, unimplemented control, unexecuted test, or unknown
residual risk may be reported as a successful security assurance result.

## Baseline contract cross-check

`KS-NET-001`–`KS-NET-042` are authoritative network requirements in
[NETWORK_SCOPE_REQUIREMENTS.md](NETWORK_SCOPE_REQUIREMENTS.md); not every
requirement has its own threat-row because some define permitted capabilities
rather than specific attacks. The existing
[NETWORK_SCOPE_VERIFICATION_PLAN.md](NETWORK_SCOPE_VERIFICATION_PLAN.md)
provides individual `MON-*`, `CTL-*`, `INT-*` and `OPS-*` cases. Threat tests
**supplement**, not replace, those requirements or their verification plan.

## M4.7 partial interface evidence

[Desktop enrollment management](../development/DESKTOP_AGENT_MANAGEMENT_M47.md)
adds read-only authorization, bounded roster validation, and explicit
unavailable-state evidence at TB-05 / I-01 / I-23, supporting TV-01, TV-06
and TV-13 without claiming operational agent or administrative GUI qualification.

## M4.8 composed authentication and transport evidence

The [M4.8 regression contract](../development/AUTHENTICATION_TRANSPORT_REGRESSIONS_M48.md)
adds mandatory controlled TLS, enrollment and KSAP failure tests for TV-06
and TV-07, with health invalidation supporting partial TV-13 evidence.
Target-host qualification is pending; operational adapters and full threat
closure remain outside this scope.

## M5.2 local journal metadata and checkpoint evidence

The [M5.2 journal contract](../development/JOURNAL_COLLECTION_M52.md) introduces
partial bounded-input, provenance, privacy and recovery evidence for the
future TB-06/TB-07 ingestion/storage boundaries. It exercises native selected
journal records, message exclusion, checkpoint recovery and a fixed capacity;
this supports TV-13, TV-25 and TV-26 (including TH-033 and TH-034), not full
coverage, disk-fault or production-storage qualification. DEP-008 introduces
an additional TB-10/TV-24 dependency review responsibility. No operational
TB-04 transport or authorization is introduced. Target-host acceptance is pending.

## M5.3 authentication observations

The [M5.3 contract](../development/AUTHENTICATION_COLLECTION_M53.md) adds partial
evidence for TB-06/TB-07 and TV-13/TV-25/TV-26 (bounded untrusted messages,
provenance, recovery and minimization). Classification is advisory; source
spoofing, completeness, correlation, and production evidence integrity are
not closed by this test. No additional privileges or external transport.

## M5.4 Linux Audit observations

The [M5.4 contract](../development/AUDIT_COLLECTION_M54.md) contributes partial
TB-06/TB-07, TV-13/TV-25/TV-26 evidence for structured audit provenance, minimization,
recovery and unavailable-source handling. No direct audit control, rule mutation
or privileged helper is introduced. Complete coverage, event assembly and
production evidence integrity remain unqualified.

## M5.5 secure telemetry buffering and delivery

The [M5.5 contract](../development/TELEMETRY_DELIVERY_M55.md) adds partial
TB-04/TB-06/TB-07, TV-06/TV-07/TV-13/TV-25/TV-26 evidence for bounded FIFO,
current enrollment, authenticated ACK, duplicate handling, backpressure and
protected state. No operational socket, complete ingestion or storage security
qualification is claimed.

## M5.6 initial file integrity monitoring

The [M5.6 contract](../development/FILE_INTEGRITY_M56.md) adds partial TB-06
and TV-13/TV-25 evidence for explicit file scope, bounded untrusted filesystem
inputs, fixed diagnostics and privacy minimization. No new privileges, raw
content persistence or operational transport; polling and race limitations
remain documented rather than claiming complete filesystem confinement.

## M5.7 privacy and data-minimization controls

The [M5.7 contract](../development/PRIVACY_MINIMIZATION_M57.md) contributes
partial TB-06/TB-07 and TV-13/TV-25/TV-26 evidence for explicit source/permit
checks, exclusion precedence, no denied-file content access, acquisition-time
redaction and rejection of old or differently bound state. Native auth fixture
and actual agent tests use synthetic data. No threat is closed; independent
policy administration, receiver-side enforcement and operational consent remain
future qualification responsibilities.

## M5.8 collector failure recovery

The [M5.8 contract](../development/COLLECTOR_RECOVERY_M58.md) adds partial
TB-06/TB-07 and TV-13/TV-26 evidence for source failures, malformed and duplicate
records, permissions, pending-file collisions, abrupt process exit and queue
backpressure, and partial TB-04/TV-06/TV-07 evidence for failed durable TLS
receipt/ACK transactions. Synthetic-only tests preserve TV-25 privacy controls.
No threat closure, power-loss proof or operational delivery is claimed.

## M5.9 local status presentation

The [M5.9 contract](../development/DESKTOP_TELEMETRY_STATUS_M59.md) adds
representative partial TB-06/TB-07 and TV-13/TV-25 evidence for minimized
aggregate status and bounded validation of untrusted local reports. Descriptor
provenance is launcher-controlled, not independently authenticated. No raw
records or private source values are published; counts/timing may be sensitive.
No operational I-07, independently authenticated status or threat closure is
claimed.

## M6.1 authenticated ingestion

The [M6.1 contract](../development/EVENT_INGESTION_M61.md) adds partial TB-04/TB-06/TB-07 and TV-06/TV-07/TV-13/TV-25/TV-26 evidence for current enrollment revalidation, canonical source binding, bounded in-flight admission, reject-only invalid input handling and durable receipt retry. Counters are local library evidence, not operational health telemetry. No threat closure or generic source ingestion qualification is claimed.

## M6.2 event normalization

The [M6.2 contract](../development/EVENT_NORMALIZATION_M62.md) contributes partial TB-06/TB-07, TH-015 and TV-10/TV-25 evidence through shared canonical validation, bounded typed mapping, exact minimized evidence retention, explicit unknown/redacted states and durable-acceptance result gating. No independent schema export, storage, operational ingestion or threat closure is claimed.

## M6.3 event storage abstraction

The [M6.3 contract](../development/EVENT_STORAGE_M63.md) provides partial
TV-10/TV-26 evidence for canonical admission, bounded capacity and query
results, conflicting evidence rejection, explicit pending/visible separation,
revision-checked retention, and held-evidence exclusion. TV-25 fixtures are
synthetic. TB-07 durable storage, legal-hold authorization, mount safety,
integrity, disk failure, persistent retention audit and threat closure remain
unqualified. The reference backend cannot authorize a durable receipt.

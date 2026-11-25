<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M4.8 — Authentication and transport security regressions

Issue #41 adds a mandatory core integration CTest across all seven presets.
It composes the existing TLS 1.3 session, protected enrollment registry and
agent health tracker with real encrypted records and ephemeral synthetic PKI.
No production code, network authorization, socket adapter, GUI or deployment
policy is changed. No external service or real credentials are used.

| Scenario | Required observation |
| --- | --- |
| Correct identity and enrollment | Fresh admission; HELLO alone is not healthy; valid heartbeat produces expected counters |
| Unknown endpoint with valid TLS; wrong pin | No enrollment side effect or trusted agent state |
| Same-connection and cross-connection ciphertext replay | Untrusted; no counters; late input rejected |
| Re-encrypted duplicate and skipped KSAP sequence | ProtocolError; no counters; terminal connection |
| Malformed magic, version, kind, flags, length and zero sequence | ProtocolError over authenticated TLS; no stale counters |
| Incomplete TLS record and incomplete KSAP frame | No new counters before disconnect; Missing and no counters after explicit transport loss |
| Fresh authenticated reconnect | No partial-frame or counter inheritance; valid fresh heartbeat succeeds |
| Revocation with queued valid heartbeat and subsequent TLS reconnect | Untrusted; no counters; admission denied even with valid TLS |
| Expired, not-yet-valid and truncated local certificate | Session creation rejected |
| Interrupted handshake | Abort terminal; no authenticated identity, plaintext or further I/O |

The existing TLS contract additionally presents a not-yet-valid peer certificate
through an independently configured OpenSSL client. Existing M4.1–M4.7
regressions remain mandatory, including role, CA, ALPN, missing certificate,
downgrade, ciphertext integrity, rotation, expiry, backpressure and clean close.

```bash
ctest --preset linux-release -R '^knetsentry_authentication_transport_regression$' --verbose --no-tests=error
ctest --preset linux-sanitize-core-only -R '^knetsentry_(authentication_transport_regression|tls_contract)$' --output-on-failure --no-tests=error
```

The new test runs in the existing hardened enrollment executable with an
explicit mode, a 30-second CTest timeout and bounded in-memory TLS pumping.
Each replay/malformed scenario establishes a new positive control before
negative input; checks require terminal rejection and absence of stale health.
The temporary owner-only registry is removed by the existing fixture destructor.
Only scenario labels are printed, not identities, credentials or ciphertext.

Traceability: I-07/I-08, TB-04, TH-003, TH-007, TH-009, TH-040 and TV-06/TV-07;
health invalidation supports partial TV-13 evidence. The test does not imply
monitoring consent or network authorization, cross-session application-level
semantic deduplication, operational socket EOF detection or complete threat
closure. Ciphertext replay and connection-local sequence replay are different
properties. A future authorized agent may send equivalent new data on a fresh
session; cross-session semantic deduplication belongs to future ingestion.
Explicit disconnect simulates adapter notification, not live socket qualification.
Maintainer acceptance on 2026-11-25 UTC: 96 PASS, 0 FAIL, 0 SKIPPED,
0 BLOCKED; all seven configured CTest suites and nine hosted checks passed
(`79c7a49`), with manual GUI verification and merge reported. See
[project status](../PROJECT_STATUS.md) for the historical evidence scope.

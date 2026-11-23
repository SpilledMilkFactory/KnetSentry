<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry — Threat Verification and Ownership Matrix

**Issue:** M0.3 / GitHub #3
**Status:** Future test specifications and accountable planned milestone owners;
**no tests listed here have yet been implemented or executed**.
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

The `TV-##` IDs are **future verification work items**, not GitHub issue numbers.

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
2. **M0.4:** Verify the eventual architecture respects `TB-01`–`TB-12`;
   assign responsibility for data origin, parser isolation, and egress.
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

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry — Initial Threat and Risk Register

**Issue:** M0.3 / GitHub #3
**Status:** Proposed design-stage risks; no mitigations are yet implemented,
verified, or accepted as residual risk.
**Model:** [THREAT_MODEL.md](THREAT_MODEL.md)
**Evidence ownership:** [THREAT_VERIFICATION_MATRIX.md](THREAT_VERIFICATION_MATRIX.md)

## Qualitative screening method

The following values are **judgment-based prioritization assumptions**, not
measurements, incident probabilities, audit results, or official NIST ratings.
They can change once the environment and controls are implemented:

- **Likelihood (`L`)**: `1` uncommon or significant prerequisites; `2`
  plausible with multiple prerequisites; `3` credible with relevant attacker
  access; `4` comparatively easy to trigger under the modeled conditions.
- **Impact (`I`)**: `1` minor; `2` moderate; `3` serious loss of reliability,
  privacy, or integrity; `4` severe unauthorized access, compromise, or
  sensitive evidence loss.
- **Screen (`L×I`)**: `1–3` Low; `4–7` Moderate; `8–11` High;
  `12–16` Critical. These are **KnetSentry-specific categories**, not NIST
  numbers; do not confuse this screen with GitHub `priority:p0`/`p1` labels.

Every entry is **OPEN / mitigation PLANNED** at M0.3. The initial score is an
**unmitigated design-stage screening estimate**. Residual scores must remain
**Not assessed** until implementation evidence and an explicit review exist.
The future owner column is an issue reference, not a claim that the issue is
open, staffed, or complete; `M3.9`, `M5.10`, `M7.10`, and `M10.9` denote the
previously proposed roadmap additions and should be confirmed on GitHub.

## Threat inventory

| ID | Boundary | STRIDE | Scenario and consequence | L | I | Screen | Planned mitigation (not implemented) | Relevant contract | Future owner | Verification |
| --- | --- | --- | --- | ---: | ---: | --- | --- | --- | --- | --- |
| `TH-001` | `TB-01` | S/T | IoT MAC/IP or DHCP spoofing merges unrelated assets and contaminates detections | 3 | 3 | **High** (9) | Confidence-scored attribution, lease history, no identity elevation from passive observation | `KS-NET-036`, `KS-NET-038` | M9.2 | `TV-02` |
| `TH-002` | `TB-01` | D | Switched/Wi-Fi topology hides suspicious IoT traffic while dashboard claims full coverage | 4 | 3 | **Critical** (12) | Coverage map, sensor-health and loss indicators; no complete-visibility claims | `KS-NET-005`, `KS-NET-034`, `KS-NET-040` | M5.10/M9.6 | `TV-02` |
| `TH-003` | `TB-01` | E | Unknown passively discovered device automatically gains management or agent privileges | 2 | 4 | **High** (8) | Separate observation and enrollment authorization; default no device control | `KS-NET-001`, `KS-NET-032`, `KS-NET-038` | M3.1/M4.4 | `TV-01` |
| `TH-004` | `TB-02` | S/T | Spoofed syslog or gateway exports create forged security events | 3 | 3 | **High** (9) | Source allowlist, authenticated export when supported, provenance and trust classification | `KS-NET-003`, `KS-NET-006`, `KS-NET-033` | M5.10/M9.4 | `TV-03` |
| `TH-005` | `TB-03` | T/E | Malformed packet or export record exploits parser memory handling | 3 | 4 | **Critical** (12) | Bounded parsing, fuzzing/sanitizers, restricted unprivileged parsing | `KS-NET-041` | M5.10/M13.3 | `TV-04` |
| `TH-006` | `TB-02` | D | Hostile telemetry flood exhausts manager CPU, queues, or memory | 4 | 3 | **Critical** (12) | Per-source quotas, bounded queues, backpressure, visible drops | `KS-NET-041` | M6.1/M14.3 | `TV-05` |
| `TH-007` | `TB-04` | S | Stolen enrolled-agent private key impersonates an endpoint | 3 | 4 | **Critical** (12) | Protected keys, mTLS identity binding, revocation/rotation, limited agent rights | `KS-NET-008`, `KS-NET-011` | M4.2/M4.5 | `TV-06` |
| `TH-008` | `TB-04` | T/R | Captured agent messages are replayed or reordered to falsify observations | 3 | 3 | **High** (9) | Sequencing, anti-replay and idempotent ingestion; source timestamps retained | `KS-NET-006`, `KS-NET-011` | M4.1/M4.8 | `TV-07` |
| `TH-009` | `TB-04` | S/E | Rogue endpoint enrolls without approval or impersonates trusted control plane | 3 | 4 | **Critical** (12) | Explicit approval, authenticated manager, enrollment state machine, cert checks | `KS-NET-011` | M4.3/M4.4 | `TV-06` |
| `TH-010` | `TB-05` | S/E | Unauthorized local process accesses privileged manager IPC | 3 | 4 | **Critical** (12) | Unix peer credential checks, role/action authorization, IPC tests | `KS-NET-012` | M2.3/M2.8 | `TV-08` |
| `TH-011` | `TB-05` | E | GUI or local user bypasses manager API to perform privileged capture or policy edit | 2 | 4 | **High** (8) | Separate service accounts and narrow privileges, GUI never root | `KS-NET-012`, `KS-NET-028` | M2.7/M13.6 | `TV-27` |
| `TH-012` | `TB-11` | T | Telemetry, AI output, or feed data changes monitoring scope or provider permission | 3 | 4 | **Critical** (12) | Typed policy, admin-only approval, no data-to-policy authority | `KS-NET-026`, `KS-NET-027` | M3.1/M3.4 | `TV-09` |
| `TH-013` | `TB-11` | T/D | Route, interface, or firewall state changes silently widen permitted egress | 3 | 4 | **Critical** (12) | Revalidation, independent nftables controls, atomic policy changes, fail closed | `KS-NET-013`, `KS-NET-014`, `KS-NET-015`, `KS-NET-028`, `KS-NET-029` | M3.3/M3.5 | `TV-09` |
| `TH-014` | `TB-06` | T/R | Clock skew or attacker-controlled event timestamps corrupt incident timelines | 4 | 2 | **High** (8) | Preserve event/receive time, drift visibility, provenance and ordering rules | `KS-NET-006` | M6.2/M10.1 | `TV-10` |
| `TH-015` | `TB-06` | T/E | Crafted event fields cause parser, query, or normalization injection | 3 | 4 | **Critical** (12) | Typed schema, safe queries, length limits, fuzzed serializers/parsers | `KS-NET-006`, `KS-NET-041` | M6.1/M6.9 | `TV-10` |
| `TH-016` | `TB-07` | T/R | On-disk evidence or database records are altered or deleted undetected | 3 | 4 | **Critical** (12) | Restricted ownership, integrity metadata, audited changes, backups | `KS-NET-006` | M6.5/M11.2 | `TV-11` |
| `TH-017` | `TB-07` | T | Attacker alters rules or suppressions to silence genuine alerts | 3 | 3 | **High** (9) | Authorized, versioned rule changes; signed audit trail strategy; regression fixtures | `KS-NET-027` | M7.5/M10.7 | `TV-12` |
| `TH-018` | `TB-12` | R/T | Incident notes or investigation history are changed without attribution | 3 | 3 | **High** (9) | Per-user audit history, immutable evidence references, authorized edits | `KS-NET-025`, `KS-NET-027` | M11.1/M11.8 | `TV-11` |
| `TH-019` | `TB-03` | D | Packet loss or exporter outage is silently interpreted as absence of threats | 4 | 3 | **Critical** (12) | Source-loss telemetry, degraded coverage state, explicit partial-data warnings | `KS-NET-034`, `KS-NET-040`, `KS-NET-041` | M5.10/M14.3 | `TV-13` |
| `TH-020` | `TB-08` | S/I | Malicious feed redirect/DNS rebinding causes internal service fetch or SSRF | 3 | 4 | **Critical** (12) | Fixed approved origins, TLS validation, resolved-IP/redirect restrictions, no untrusted URL fetch | `KS-NET-018`, `KS-NET-019`, `KS-NET-020` | M3.9 | `TV-14` |
| `TH-021` | `TB-08` | T/E | Malformed public feed exploits parser or corrupts local indicator data | 3 | 4 | **Critical** (12) | Size/schema caps, sandboxed parsing decision, validation/quarantine, safe cache | `KS-NET-018`, `KS-NET-024` | M10.9/M13.3 | `TV-15` |
| `TH-022` | `TB-08` | T | Stale or poisoned intelligence causes false CVE or threat conclusions | 4 | 3 | **Critical** (12) | Feed provenance, timestamps, validation, confidence, stale-data indicators | `KS-NET-023`, `KS-NET-024`, `KS-NET-042` | M10.9 | `TV-15` |
| `TH-023` | `TB-08` | I | Indicator/CVE lookup leaks private asset context or raw logs to provider | 3 | 4 | **Critical** (12) | Opt-in, minimize queries, no private telemetry upload, privacy/audit UI | `KS-NET-016`, `KS-NET-017`, `KS-NET-021`, `KS-NET-025` | M3.9/M10.9 | `TV-16` |
| `TH-024` | `TB-09` | T/E | Prompt injection in log/incident text steers AI toward unsafe recommendations | 4 | 3 | **Critical** (12) | Untrusted-context separation, constrained tools, validated output, human approval | `KS-NET-020`, `KS-NET-022` | M12.6/M12.9 | `TV-17` |
| `TH-025` | `TB-09` | T/E | Unverified model artifact loads malicious code or unsafe resources | 3 | 4 | **Critical** (12) | Format and provenance checks, model approval, isolated inference execution | `KS-NET-022`, `KS-NET-024` | M12.2/M12.3 | `TV-18` |
| `TH-026` | `TB-09` | D/I | Inference process exhausts resources or discloses sensitive event context | 4 | 3 | **Critical** (12) | Memory/CPU caps, no egress, data minimization, restricted IPC | `KS-NET-021`, `KS-NET-022` | M12.2/M12.9 | `TV-19` |
| `TH-027` | `TB-12` | E/D | False alert initiates unauthorized isolation or disruptive remediation | 3 | 4 | **Critical** (12) | Response disabled by default; explicit approval; narrow actions and audit | `KS-NET-027` | M11.5 | `TV-20` |
| `TH-028` | `TB-12` | I | Incident export reveals private flows, credentials, or identifiers | 3 | 4 | **Critical** (12) | Authorized export, redaction, path-safe writes, review before disclosure | `KS-NET-021`, `KS-NET-025` | M11.6/M11.8 | `TV-21` |
| `TH-029` | `TB-01` | S/T | Heuristic OUI/vendor match falsely declares a confirmed IoT CVE | 4 | 3 | **Critical** (12) | Confidence-aware identity/firmware evidence, no unsupported applicability claim | `KS-NET-036`, `KS-NET-042` | M9.2/M10.9 | `TV-22` |
| `TH-030` | `TB-01` | D | Active discovery harms fragile device or probes unauthorized external peer | 3 | 3 | **High** (9) | Passive default; explicit scoped opt-in with rate caps and audit | `KS-NET-003`, `KS-NET-039` | M3.1/M9.5 | `TV-23` |
| `TH-031` | `TB-10` | T/E | Compromised third-party dependency introduces malicious runtime behavior | 3 | 4 | **Critical** (12) | Dependency provenance, pinning, audit, SBOM, source review | `KS-NET-024` | M0.6/M13.7 | `TV-24` |
| `TH-032` | `TB-10` | S/T | Compromised CI or package/update path ships altered executable | 3 | 4 | **Critical** (12) | Restricted release workflow, artifact provenance, verified upgrades | `KS-NET-024` | M1.8/M15.5 | `TV-24` |
| `TH-033` | `TB-07` | I | Secrets or raw private telemetry leak through diagnostic logging | 4 | 3 | **Critical** (12) | Structured redaction, negative tests, protected permissions and retention | `KS-NET-021`, `KS-NET-025` | M1.6/M13.1 | `TV-25` |
| `TH-034` | `TB-07` | D | Event storage fills disk, breaks collection, or damages host availability | 4 | 3 | **Critical** (12) | Retention quotas, backpressure, bounded spool, disk-full regression | `KS-NET-041` | M6.7/M14.4 | `TV-26` |
| `TH-035` | `TB-07` | T/D | Crash during schema migration leaves irrecoverable or inconsistent evidence | 3 | 3 | **High** (9) | Transactional migrations, backups, restore testing, version checks | `KS-NET-006` | M6.4/M14.4 | `TV-30` |
| `TH-036` | `TB-03` | I | Raw packet payloads are captured or retained without administrator consent | 3 | 4 | **Critical** (12) | Metadata-first default, separately approved capture, access and retention controls | `KS-NET-003`, `KS-NET-035`, `KS-NET-041` | M5.10/M9.5 | `TV-01` |
| `TH-037` | `TB-05` | S/E | Stolen administrator session changes source approvals or case access | 3 | 4 | **Critical** (12) | Strong local session auth, action authorization, audit, privilege boundaries | `KS-NET-027` | M2.3/M11.1 | `TV-29` |
| `TH-038` | `TB-05` | I/E | Manager mistakenly binds administrative API to public network interface | 3 | 4 | **Critical** (12) | Unix IPC by default, explicit socket paths, no remote listener, network tests | `KS-NET-012`, `KS-NET-028` | M2.3/M3.5 | `TV-28` |
| `TH-039` | `TB-09` | I | Inference worker inherits manager Internet egress and contacts cloud service | 3 | 4 | **Critical** (12) | No worker network access, OS isolation, egress denial checks | `KS-NET-022`, `KS-NET-028` | M12.2/M13.5 | `TV-19` |
| `TH-040` | `TB-04` | S/E | Compromised enrollment issuer or unchecked certificate identity yields forged agents | 2 | 4 | **High** (8) | Restricted CA key, chain and identity validation, rotation and revocation | `KS-NET-011` | M4.2/M4.5 | `TV-06` |
| `TH-041` | `TB-08` | S | External provider DNS answer or HTTP proxy substitutes an unauthorized destination | 3 | 4 | **Critical** (12) | Validate resolved and connected IP, explicit proxy policy, peer TLS identity | `KS-NET-018`, `KS-NET-019` | M3.9 | `TV-14` |
| `TH-042` | `TB-06` | T/D | Data poisoning exploits noisy input to trigger false alerts or conceal real ones | 4 | 3 | **Critical** (12) | Rule fixtures, source-confidence metadata, suppression review, alert evidence | `KS-NET-006`, `KS-NET-037` | M7.8/M10.8 | `TV-12` |

## Risk treatment and audit workflow

Every register item is currently **Open / planned**. No risk is marked
mitigated, accepted, or closed by the creation of these documents. For future
risk updates, retain the original scenario, add an evidence reference
(commit, CI run, test report, or reviewed analysis), assign a decision owner,
and record actual residual risk with its rationale and review date. A
successful test can validate one control but does not prove the entire threat
has been eliminated.

At implementation time, issues that materially change a trust boundary should
review related rows before merge. M13's security assessment and M15's release
audit must examine any unresolved high/critical risks against implemented
controls and documented conditions; a release-blocking finding prevents
sign-off unless resolved through the release process.

**Residual risk for all `TH-001`–`TH-042`: Not assessed.**

## Notes on source truth

- Source-validation failures are distinguishable from device compromise.
- Passive discovery of an unknown IoT device does not confer trust.
- "Device has a CVE" requires defensible identity and affected-version
  evidence; a vendor heuristic is insufficient.
- A missing packet or detection is not proof that no incident occurred.
- Agent and feed data remains untrusted **even if transport is authenticated**.

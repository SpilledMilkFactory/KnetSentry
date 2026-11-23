<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Reliability, Recovery, and Degradation Plan

**Issue:** M0.5. **Status:** proposed resilience gates; they will only be
considered verified after implementation and fault-injection testing.

## 1. Core principles

A high event rate is not useful if the SIEM silently loses information or
misleads the operator about its own coverage. Maintain distinct counters for
observed/attempted packet capture, kernel capture loss, raw source records,
transport retries, rejected records, queued items, durable acknowledgments,
indexed records, and alerts. **Never infer missing records from an absent
counter.** All critical recovery states are auditable.

No network-performance optimization is allowed to disable source authority,
non-root GUI isolation, feed egress policy, telemetry provenance, or explicit
monitoring scope. External intelligence and offline AI cannot block core
sensor processing or deterministic detection.

## 2. Failure matrix

| Failure ID | Injection / trigger | Required visible behavior | Proposed acceptance | Owner |
| --- | --- | --- | --- | --- |
| `F-01` | Agentless sensor disconnected (W-06) | Coverage becomes degraded with last-seen time and affected source IDs | Detected <= 90 s beyond heartbeat/export deadline | M5.10/M9.6 |
| `F-02` | Manager process crash/restart (W-06) | Restart state and clear gap attribution; recover durable records | Healthy <= 120 s; no lost acknowledged records | M14.4 |
| `F-03` | Transport interruption (W-06) | Bounded spool, retry and deduplication visible | 30 min at 10 EPS/source when quota adequate | M5.5 |
| `F-04` | Burst beyond sustained capacity (W-02) | Queues bounded, backlog reported, suppression/loss visible | Drain <= 5 min at baseline load; no unreported loss | M14.3 |
| `F-05` | Disk nearly full / quota exhaustion | Warn and reject/degrade predictably; honor protected evidence | Reserve >= max(5 GiB, 10%); no silent deletion | M6.7/M14.3 |
| `F-06` | SQLite interrupted write / corrupted index | Integrity check and recovery or explicit failure | No false success; affected records/status identified | M14.4 |
| `F-07` | Capture ring overflow (W-03/W-04) | Kernel and application drop counters exposed | W-03 <= 0.5% measured drops; any loss reported | M5.10/M14.1 |
| `F-08` | Cloud/feed unreachable or AI disabled (W-07) | Local SIEM continues; feed freshness becomes visible | Core ingest, detect, search and GUI remain functional | M10.9/M12.2 |
| `F-09` | Clock skew / altered source timestamp | Preserve original and receipt timestamps, flag uncertainty | No fabricated global ordering or invalid latency claim | M6.2/M14.1 |
| `F-10` | Restore from backup | Report recovery and integrity verification evidence | Measure RPO and RTO; no unsupported recovery claim | M14.6 |
| `F-11` | Unauthorized scope or policy change | Affected network operation denied; coverage status degraded | Existing M0.2/M0.3 security gates remain binding | M3/M13 |
| `F-12` | Long run with source churn (W-01) | No unbounded queues/leaks; counter continuity | 24 h representative soak with captured evidence | M14.5 |

| `F-13` | Approved removable raw storage unmounted mid-ingest | Mount identity mismatch and stopped raw persistence; no transparent OS-disk fallback | No raw records written to vacated mount path; no false durable ACK | M6.3/M14.4 |
| `F-14` | Different volume mounted at same raw path | Explicit device identity mismatch and denial until reauthorized | No silent trust of replacement despite identical path | M6.3/M13.6 |
| `F-15` | Raw drive becomes read-only, fails I/O, or hits quota | Raw-first stage degrades; new ACKs refused; optional dedicated spool only if opted in | No unreported acknowledged event loss; bounded resource use | M6.5/M14.3 |
| `F-16` | SQLite/index store unavailable after raw segment committed | Original raw record retained; searchable index marked pending; replay on recovery | No fabricated indexed success, durable replay linked by stable ID | M6.4/M14.4 |
| `F-17` | Storage migration interrupted or denied | Old store remains authoritative until integrity-checked cutover; rollback and audit | No data overwrite or loss of protected evidence; auditable outcome | M14.6 |
| `F-18` | Unsafe folder, symlink switch, unsupported network FS or permission mismatch | Reject activation as manager, display corrective UI reason | No privilege escalation, unauthorized writes or unsafe SQLite WAL | M6.3/M13.6 |

## 3. Definitions and recovery targets

- **RTO:** elapsed time from declared service interruption until a defined
  healthy endpoint and accepted/visible event path return; record endpoint
  identity, detection-health and query-state checks. The initial manager RTO
  target is **120 seconds** for the controlled crash fixture on the reference
  deployment, not arbitrary hardware/power-loss recovery.
- **RPO:** age/amount of correctly acknowledged durable data irrecoverably
  missing at restoration. Planned target: **zero acknowledged records lost**
  in controlled crash/restart, with the actual fault model documented. No
  blanket guarantee for never-acknowledged packets or failed storage devices.
- **Queue admission:** finite per-hop capacity with documented overflow
  behavior. Retry is at least once with stable identity and bounded replay;
  exactly-once transport is not assumed.
- **Source outage reporting:** deadline-based monitoring. The 90-second target
  begins after the configured heartbeat/export deadline, not at an unknown
  moment of last packet visibility.
- **Unavailable source versus quiet network:** a quiet device cannot be
  declared compromised or healthy simply because no events were observed.

## 4. Verification ownership

Each failure scenario has a benchmark in
[BENCHMARK_PLAN.md](BENCHMARK_PLAN.md) and references
[requirements](PERFORMANCE_REQUIREMENTS.md). Controls remain **unimplemented**
through M0.5; M5–M14 implement, test and report the actual behavior.

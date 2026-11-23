<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Performance, Reliability and Resource Requirements

**Issue:** M0.5. **Status:** proposed initial **engineering qualification targets**, not
measured results, implemented protections, guaranteed capacity, or hardware minimums.

## 1. Scope and measurement definitions

The first v1.0.0 target remains Ubuntu 26.04 LTS AMD64. Agentless gateway and
passive-sensor sources are **first-class**, and a KnetSentry endpoint agent is
optional. Approved external CVE/MITRE synchronization remains permitted but is
not required for core operation. Every capacity evaluation must distinguish:

- **Observed packets/s (PPS):** packets actually delivered to an approved
  capture interface. PPS is never equivalent to an event count; a packet may
  yield zero, one, or multiple interpreted records.
- **Source records/s:** raw records arriving from a gateway, sensor, journal,
  or optional agent; may be duplicated or invalid.
- **Accepted normalized events/s (EPS):** validated events passing ingestion
  and admitted into durable processing; record rejected/duplicate counts.
- **Alert output/s:** rule results; a detection can involve several events.
- **Durability:** report time from manager-receipt to completed persistent
  write and query visibility. Sender acknowledgments must not precede the
  documented durability point.
- **Visibility:** observed, partial, degraded and unavailable coverage states
  cannot be collapsed into a single success percentage.
- **Percentiles:** nearest-rank p50/p95/p99 over reported completed samples;
  excluded/time-out samples must be counted separately. Limits apply at the
  workload interval specified below, not averaged across idle time.

Targets apply to a **declared reference host** meeting the documented benchmark
profile in [workloads](WORKLOAD_PROFILES.md); actual hardware specifications
must be recorded and cannot be invented during M0.5. An unmeasured target is
`NOT_RUN`, never `PASS`. A measured miss is `FAIL` until review and a tracked
revision; security requirements cannot be reduced to attain throughput.

## 2. Traceable requirements

Each `KS-PERF-*` entry has a verifiable threshold or observable outcome, a
future milestone owner, and a mapped benchmark identifier in the
[benchmark plan](BENCHMARK_PLAN.md). The number is an initial engineering bar;
revisions require an ADR/review record and corresponding test updates.

| ID | Requirement | Initial acceptance criterion | Owner | Test |
| --- | --- | --- | --- | --- |
| `KS-PERF-001` | Bench profiles | W-01 through W-07 must be exercised; zero-load control W-00 is mandatory. | M14.1 | `BT-01` |
| `KS-PERF-002` | Reference deployment | An Ubuntu 26.04 AMD64 manager, local GUI, and authorized agentless gateway or sensor are mandatory. | M14.1 | `BT-01` |
| `KS-PERF-003` | Source mix | Test 10 simultaneous approved reporting sources (at least one agentless; optional agents not prerequisite). | M14.2 | `BT-02` |
| `KS-PERF-004` | Sustained EPS | Accept 100 aggregate normalized events/s for 60 min on W-01 (360,000 injected events). | M14.1 | `BT-03` |
| `KS-PERF-005` | Burst EPS | Accept 1,000 aggregate normalized events/s for 60 s on W-02 (60,000 injected events). | M14.1 | `BT-04` |
| `KS-PERF-006` | Packet capacity | Target 2,000 observed packets/s for 30 min on W-03; keep packets/s separate from events/s. | M14.1 | `BT-05` |
| `KS-PERF-007` | Packet burst | Target 10,000 observed packets/s for 60 s on W-04; no remote host probing. | M14.1 | `BT-05` |
| `KS-PERF-008` | Source authenticity | All runs preserve and record source trust, observation scope, attribution confidence, and coverage. | M5.10 | `BT-02` |
| `KS-PERF-009` | Event durability latency | W-01: p95 <= 2 s and p99 <= 5 s from manager receipt to durable/query-visible record. | M14.1 | `BT-06` |
| `KS-PERF-010` | Detection latency | W-01: simple built-in alert p95 <= 10 s and p99 <= 30 s after manager receipt. | M14.1 | `BT-06` |
| `KS-PERF-011` | Search responsiveness | W-05: p95 <= 2 s for bounded indexed query over a seven-day-sized reference dataset. | M14.7 | `BT-07` |
| `KS-PERF-012` | GUI interactions | W-05: p95 <= 200 ms for local navigation/filter initiation, excluding server query time. | M8.9 | `BT-08` |
| `KS-PERF-013` | GUI rendering | W-05: p95 frame interval <= 50 ms during subscribed live updates on the reference desktop. | M8.9 | `BT-08` |
| `KS-PERF-014` | Latency measurement | Record monotonic timing for same-host stages; cross-host wall-clock tests require measured skew bound. | M14.1 | `BT-06` |
| `KS-PERF-015` | Latency transparency | Report p50, p95, p99, maximum, sample counts, error rates, and skipped samples. | M14.1 | `BT-06` |
| `KS-PERF-016` | Manager memory | W-01: manager service RSS <= 1536 MiB after warm-up, excluding separately isolated workers. | M14.1 | `BT-09` |
| `KS-PERF-017` | Sensor memory | W-03: sensor worker and broker combined RSS <= 512 MiB after warm-up. | M14.1 | `BT-09` |
| `KS-PERF-018` | Agent memory | W-01: optional endpoint agent RSS <= 256 MiB per agent; agentless runs remain required. | M14.2 | `BT-09` |
| `KS-PERF-019` | Desktop memory | W-05: desktop RSS <= 1024 MiB during an extended live workspace session. | M8.9 | `BT-09` |
| `KS-PERF-020` | Manager CPU | W-01: manager average CPU <= 200% of one logical CPU, with CPU topology recorded. | M14.1 | `BT-09` |
| `KS-PERF-021` | Worker pressure | Record process/cgroup CPU, I/O and memory pressure plus peak RSS and page faults per run. | M14.1 | `BT-09` |
| `KS-PERF-022` | Capture loss | W-03: captured packet loss <= 0.5% when the delivered reference traffic is independently counted. | M14.1 | `BT-10` |
| `KS-PERF-023` | Loss observability | Any nonzero source, kernel capture, queue, or downstream drop count must be surfaced as degraded. | M14.3 | `BT-10` |
| `KS-PERF-024` | Acknowledged records | No previously acknowledged durable events may disappear in W-01/W-02, including restart verification. | M14.4 | `BT-11` |
| `KS-PERF-025` | Delivery semantics | At-least-once retry with stable event identity; replay cannot create unbounded duplicate records. | M5.5 | `BT-11` |
| `KS-PERF-026` | Queue bounds | Every ingress and transport queue has a documented finite limit and defined overload policy. | M14.3 | `BT-12` |
| `KS-PERF-027` | Burst recovery | Following W-02, backlog drains within 5 min under resumed 100 events/s input without dropping acknowledged data. | M14.3 | `BT-12` |
| `KS-PERF-028` | Disconnected source buffer | W-06: at least 30 min buffering at 10 events/s/source when provisioned quota suffices; report quota exhaustion. | M5.5 | `BT-13` |
| `KS-PERF-029` | Source outage detection | W-06: declare absence of expected heartbeat/export <= 90 s after configured deadline. | M4.6 | `BT-13` |
| `KS-PERF-030` | Manager restart | W-06: manager returns to healthy operation within 120 s after controlled crash/restart. | M14.4 | `BT-14` |
| `KS-PERF-031` | Integrity after restart | W-06: stored records, query indexes and detection checkpoints recover consistently or fail visibly. | M14.4 | `BT-14` |
| `KS-PERF-032` | Offline independence | W-07: core ingest, store, detection and GUI function without external feeds or AI. | M14.5 | `BT-15` |
| `KS-PERF-033` | Storage arithmetic | Estimate retention from actual event sizes, index amplification, spool, raw capture, backups, WAL and reserve. | M14.8 | `BT-16` |
| `KS-PERF-034` | Retention flexibility | Support explicitly configured 24 h and 7 d logical retention if capacity plan approves; no blanket disk promise. | M6.7 | `BT-16` |
| `KS-PERF-035` | Disk reserve | Require a configured reserve of at least max(5 GiB, 10% of data volume) and predictable low-space behavior. | M14.3 | `BT-17` |
| `KS-PERF-036` | Retention integrity | Quotas and pruning cannot silently discard legal holds or protected incident evidence. | M11.2 | `BT-17` |
| `KS-PERF-037` | Soak | W-01 representative activity and source churn for 24 h without unbounded growth, deadlock or silent loss. | M14.5 | `BT-18` |
| `KS-PERF-038` | Backup/restore | Record backup duration, restore duration, integrity verification, and effective RPO/RTO on W-06 data. | M14.6 | `BT-19` |
| `KS-PERF-039` | Benchmark provenance | Each result includes OS/kernel/tool versions, hardware, configuration, seed, source hashes and actual workloads. | M14.8 | `BT-20` |
| `KS-PERF-040` | Security invariants | No performance result can waive authorization, data provenance, least privilege, or network boundary controls. | M13.8 | `BT-21` |

| `KS-PERF-041` | Configurable raw store | Administrator selects an explicit raw event directory on a locally mounted volume, including a volume separate from the OS. Preserve selection across restarts; no forced OS-disk placement. | M6.3 | `BT-22` |
| `KS-PERF-042` | Graphical folder selection | Qt 6/Kirigami settings expose a native or desktop-integrated graphical directory picker and show filesystem, mount, usable bytes, reserve, and validation outcome before activation. | M8.10 | `BT-22` |
| `KS-PERF-043` | Authorization and path safety | Manager validates access under its actual service identity and rejects unsafe symlinks, traversal, untrusted reparse paths, world-writable parents, and unapproved network filesystems. GUI user permissions alone are insufficient. | M6.3 | `BT-27` |
| `KS-PERF-044` | Mounted volume eligibility | Support locally mounted qualified filesystems where durability, ownership, access control, locking and required operations are validated. Removable volumes require explicit acknowledgement; network filesystems unsupported for v1.0 raw and SQLite stores until separately qualified. | M6.3 | `BT-27` |
| `KS-PERF-045` | Stable destination identity | Bind raw store configuration to expected underlying volume identity plus canonical directory; validate at startup, reopen, configuration change and before each new segment. A path existing on a different filesystem is NOT the approved store. | M6.3 | `BT-23` |
| `KS-PERF-046` | No silent OS fallback | Unmounted/replaced/read-only/absent raw volume must never cause raw records to be written to an empty mount directory on the OS drive or another fallback path unless explicitly configured and separately authorized. | M6.3 | `BT-23` |
| `KS-PERF-047` | Raw-first pipeline | For permitted source records intended for preservation, write bounded privacy-filtered original bytes with stable provenance and integrity metadata to the approved raw store before normalization/indexing; disallowed packet payload capture remains off by default. | M6.5 | `BT-24` |
| `KS-PERF-048` | Durable state transitions | Distinguish RECEIVED, RAW_DURABLE, INDEX_PENDING, INDEXED and FAILED/DEGRADED. A durable acknowledgment references only the stage actually committed with a tested durability barrier; indexing failures remain visible and replayable. | M6.5 | `BT-24` |
| `KS-PERF-049` | Separate index location | Raw event path and SQLite indexed-event database path are independently configurable and capacity-checked. SQLite WAL, shm, temp and checkpoints must remain on a supported local filesystem with safe locking and documented paths. | M6.4 | `BT-25` |
| `KS-PERF-050` | Volume-specific capacity | Per-volume high-watermark, free-space reserve >= max(5 GiB,10% of data volume), quota, spool/WAL/tmp/backup estimate and depletion forecast must be reported independently; no hidden writes outside configured storage roles. | M6.7 | `BT-25` |
| `KS-PERF-051` | Detachment and exhaustion | On raw-store loss, read-only transition, full disk, I/O faults or changed mount, refuse new raw durable acknowledgments; enter visibly degraded state and use only a separately opted-in bounded spool, otherwise fail closed/reject. | M14.4 | `BT-23` |
| `KS-PERF-052` | Migration and switching | Changing storage location requires authorized preflight, space estimation, quiescing or immutable segment rollover, integrity checks, atomic cutover and recoverable rollback with explicit copy-versus-move and evidence-hold rules. | M14.6 | `BT-26` |
| `KS-PERF-053` | Confidentiality and retention | Service-scoped filesystem permissions, audit of path changes, retention and protected evidence holds apply across volumes; removable evidence encryption requirements and export rules must be reviewed before enablement. | M6.5 | `BT-27` |
| `KS-PERF-054` | Placement performance | Measure raw-durable latency, index lag, I/O throughput, segment fsync and retention sizing on same-volume and separate-volume reference configurations; report device and filesystem details. | M14.1 | `BT-28` |

### Storage-location interpretation

The raw store is a secure, administrator-authorized destination for **permitted original source records**, not a requirement to retain full packet payloads. Privacy/retention rules apply **before** raw persistence. A rejected or prohibited payload must not be preserved merely to satisfy raw-first ordering. Raw segments and database indexes are different storage roles; neither directory selection nor volume mounting is delegated to a root-running GUI. Implementation and performance evidence remain future M6/M8/M14 work.

## 3. Scope limits and qualifications

The packet throughput targets above concern **authorized controlled replay**
through suitable capture interfaces, not traffic injected into the user's
actual LAN. The PPS objective is measured independently from normalized EPS.
Do not assume a network segment is fully visible merely because packet or
record throughput met a target. Timestamp skew, NAT, encrypted traffic,
source loss and routing blind spots must accompany metrics where relevant.

`KS-PERF-024` guarantees consistency only for records correctly acknowledged
under the implemented durable-ack contract. It does **not** promise recovery
of never-received packets, unacknowledged in-flight data, or all events after
uncontrolled host/storage failure. Requirements for source degradation,
local-only operation and restricted external feed access remain binding.

[Storage sizing](RESOURCE_CAPACITY_MODEL.md) is workload-based. Seven days at
100 EPS is a **sizing scenario**, not a default retention guarantee or claim
that a small Ubuntu workstation has enough disk. Raw packet payload retention
is off unless separately enabled and approved. AI memory and CPU are measured
separately and do not silently count against core-service budgets.

## 4. Reference methodology

See [workload profiles](WORKLOAD_PROFILES.md),
[benchmark methodology](BENCHMARK_PLAN.md),
[storage model](RESOURCE_CAPACITY_MODEL.md),
[recovery matrix](RELIABILITY_RECOVERY_PLAN.md), and
[result template](BENCHMARK_RESULT_TEMPLATE.md).

These requirements depend on the [M0.4 architecture](../architecture/SYSTEM_ARCHITECTURE.md),
[agentless deployment profiles](../architecture/DEPLOYMENT_TOPOLOGIES.md),
[M0.2 network controls](../security/NETWORK_SCOPE_REQUIREMENTS.md), and
[M0.3 threat model](../security/THREAT_MODEL.md). Application and security
qualifications are deferred to their owning issues; this milestone adds no
runtime functionality or benchmark scores.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Benchmark Methodology and Acceptance Plan

**Issue:** M0.5. **Status:** reproducible **future qualification plan** only;
no benchmark harness, benchmark output, or performance certification exists.

## 1. Qualification principles

- A *PASS* requires an actual reproducible run on the declared Ubuntu 26.04
  AMD64 reference system, with complete input and output counts, counter
  provenance, and report artifacts. Documentation validation is not a PASS.
- Performance and security acceptance are distinct gates; higher throughput
  cannot excuse lost audit trails, relaxed network scope or elevated parsing.
- Tests involving packets run only in approved isolated namespaces or a
  dedicated consented lab. Never generate disruptive RFC 2544-style traffic
  on an occupied LAN; [RFC 6815](https://www.rfc-editor.org/rfc/rfc6815.html)
  cautions against production-network use of such methodologies.
- A benchmark run may be `PASS`, `FAIL`, `INVALID_RUN` (faulty stimulus or
  environment), `INCOMPLETE` (missing required evidence), or `NOT_RUN`.
  A target should not be silently revised after a failure.

## 2. Benchmark matrix

| ID | Workload | Required evidence / exercise | Requirement IDs | Owner |
| --- | --- | --- | --- | --- |
| `BT-01` | `W-00/W-01` | Reference host metadata, idle state and deployment checks | `KS-PERF-001`, `002` | M14.1 |
| `BT-02` | `W-01` | Ten reporting sources, one without agent, and provenance status | `KS-PERF-003`, `008` | M14.2 |
| `BT-03` | `W-01` | Sustained 100 EPS, submitted-versus-durable counts | `KS-PERF-004` | M14.1 |
| `BT-04` | `W-02` | One minute 1,000 EPS with stable identity | `KS-PERF-005` | M14.1 |
| `BT-05` | `W-03/W-04` | Independently counted 2,000/10,000 PPS, isolation verified | `KS-PERF-006`, `007` | M14.1 |
| `BT-06` | `W-01` | Receipt-to-durable and receipt-to-alert percentiles, clocks validated | `KS-PERF-009`, `010`, `014`, `015` | M14.1 |
| `BT-07` | `W-05` | Indexed query results over reference 7-day dataset | `KS-PERF-011` | M14.7 |
| `BT-08` | `W-05` | Qt GUI latency, frame intervals and user-action probes | `KS-PERF-012`, `013` | M8.9 |
| `BT-09` | `W-00/W-01/W-03/W-05` | RSS/CPU/PSI/resource sampling for all process roles | `KS-PERF-016`, `017`, `018`, `019`, `020`, `021` | M14.1 |
| `BT-10` | `W-03/W-04` | Capture packet loss and degradation indicators | `KS-PERF-022`, `023` | M14.1 |
| `BT-11` | `W-01/W-02/W-06` | Durable acknowledgment reconciliation and duplicate replay | `KS-PERF-024`, `025` | M14.4 |
| `BT-12` | `W-02` | Queue high-water, overload response and drain timing | `KS-PERF-026`, `027` | M14.3 |
| `BT-13` | `W-06` | Disconnected source 30 minutes, spool quota and outage warning | `KS-PERF-028`, `029` | M5.5 |
| `BT-14` | `W-06` | Crash/restart durability and indexed/detection recovery | `KS-PERF-030`, `031` | M14.4 |
| `BT-15` | `W-07` | Offline core functionality with denied external connections | `KS-PERF-032` | M14.5 |
| `BT-16` | `W-01/W-05` | Measured bytes/event, 24-hour and 7-day admission model | `KS-PERF-033`, `034` | M14.8 |
| `BT-17` | `W-06` | Disk-reserve, holds and safe quota-exhaustion behavior | `KS-PERF-035`, `036` | M14.3 |
| `BT-18` | `W-01` | 24-hour soak, source churn and no sustained growth | `KS-PERF-037` | M14.5 |
| `BT-19` | `W-06` | Backup, restore, integrity and measured RTO/RPO | `KS-PERF-038` | M14.6 |
| `BT-20` | `ALL` | Reproducibility provenance and run artifact manifest | `KS-PERF-039` | M14.8 |
| `BT-21` | `ALL` | Privilege and network controls remain enforced under load | `KS-PERF-040` | M13.8 |

| `BT-22` | `W-08` | GUI browse/selection, permissions preview and independent raw/index destinations | `KS-PERF-041`, `KS-PERF-042` | M8.10 |
| `BT-23` | `W-09` | Unmount, mount substitution, read-only/full volume; no writes to fallback root path or false ACK | `KS-PERF-045`, `KS-PERF-046`, `KS-PERF-051` | M14.4 |
| `BT-24` | `W-08/W-09` | Raw original durability before normalization; index outage leaves replayable originals with honest status | `KS-PERF-047`, `KS-PERF-048` | M6.5 |
| `BT-25` | `W-08` | Separate raw/index quotas, independent free-space and WAL/tmp location | `KS-PERF-049`, `KS-PERF-050` | M14.3 |
| `BT-26` | `W-09` | Authorized relocation, integrity, safe cutover, rollback and evidence hold preservation | `KS-PERF-052` | M14.6 |
| `BT-27` | `W-09` | Symlink, path, permissions, network FS, removable encryption/retention policy tests | `KS-PERF-043`, `KS-PERF-044`, `KS-PERF-053` | M13.6 |
| `BT-28` | `W-08` | Same-volume versus separate-volume latency, CPU, I/O, capacity and durability report | `KS-PERF-054` | M14.1 |

## 3. Standard procedure

1. Record repository commit, binary hashes, dependency lock, compiler, kernel,
   OS release, CMake/Qt/KDE versions and exact effective configuration.
2. Inventory CPU topology, RAM, filesystem, disk, NIC, offloading, CPU
   governor, power/thermal state, cgroup limits, container/VM status,
   and data location. Note any deviations from prior runs.
3. Generate immutable fixture data with seed and SHA-256; inventory event-size
   distribution and expected per-source counts before execution.
4. Establish clean state and `W-00` control, declare cache warm/cold policy,
   and measure background system load. Use at least three independent runs.
5. For each workload capture source/generator counts, broker and kernel drops,
   parser count, ingress/reject/duplicate count, persistent acknowledgments,
   searchable count, alert count, resource samples and failure diagnostics.
6. Use monotonic timestamps for in-process stages. For cross-machine
   measurement, capture wall-clock offset/skew and label uncertainty. Report
   p50, p95, p99, max, timeouts, incomplete samples and confidence limits.
7. Generate per-run JSON/CSV counters and summary Markdown plus raw logs
   (synthetic/consented and redacted), run manifest, fixture hashes and
   crash artifacts; preserve enough information for independent reproduction.
8. Compare each requirement to its defined profile only; missing counters or
   misconfigured replay causes `INCOMPLETE`/`INVALID_RUN`, not a quiet PASS.
9. Store environment and baseline deltas; track failed gates and corrective
   issues rather than changing the release bar without review.

### Two-volume storage qualification

For `W-08` and `W-09`, record mount/volume identity and capacity for **both**
raw event segments and indexed SQLite/WAL/temp files. Compare single-drive
versus separated-drive configurations with equal event fixtures. After a
forced mount loss, independently inspect the vacated OS-drive mount directory:
**zero** new raw records may appear there. Verify that an index outage leaves
raw-durable originals replayable and query coverage explicitly degraded.
Use an isolated removable/mounted test volume; do not unmount an active system
volume or touch real sensitive evidence during qualification.

## 4. Measurement ownership and instrumentation

| Stage | Instrumentation planned | Why needed |
| --- | --- | --- |
| Packet source and kernel | Independent generator/NIC counts; `PACKET_STATISTICS` or equivalent | Distinguish packets never delivered from packets dropped during capture |
| Capture broker and parser | In/out counters, rejected frames, queue depth, parse time | Identify capture/parser bottlenecks and exploit-driven overload |
| Gateway/agent transport | Source IDs, retries, authorization rejects, spool occupancy | Separate network loss, authentication and replay |
| Ingestion/storage | Receipt, validation, durable ACK, index visibility, bytes written, WAL | Measure EPS, write latency, and durability point |
| Detection/alert | Rule start/end, evidence counts, alert acknowledgment | Measure investigation-relevant latency |
| Qt UI | Visible interaction trace, query wait, frame-time sampling | Avoid conflating GUI work with backend query latency |
| Host resources | `/proc`, cgroups, CPU, RSS/PSS, I/O, `/proc/pressure/*` if available | Reveal throttling, swapping, and saturating disk queues |

Linux packet ring stats can expose drops, but capture stats by themselves are
not proof of end-to-end delivery; see
[Linux Packet MMAP](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html).
Linux PSI sampling can help explain high-tail latencies; see
[kernel documentation](https://docs.kernel.org/accounting/psi.html).

## 5. Reporting and acceptance

Use [the result template](BENCHMARK_RESULT_TEMPLATE.md). Aggregate a gate
only after **all required iterations** pass with complete evidence or a
predefined aggregation rule documented before testing. Report warm and cold
results separately where relevant. If environment changes, compare results
only with compatible baselines. Declare any unsupported configuration as
outside the tested release envelope rather than extrapolating a benchmark.

Owner mapping is provisional to the existing GitHub roadmap. M0.5 creates
requirements; M5/M6/M8/M13/M14/M15 supply implementation, test harnesses and
release-candidate evidence.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry — Storage and Resource Capacity Model

**Issue:** M0.5. **Status:** planning examples, not measured compression,
actual database amplification, guaranteed retention, or minimum hardware.

## 1. Capacity formulas

Use separately metered mean **persisted bytes per accepted event** (event body
plus actual database/WAL/index overhead), not just serialized event size.
Initial estimate, in decimal bytes:

`raw_event_bytes = accepted_EPS * 86,400 * retained_days * mean_permitted_original_bytes`

`index_bytes = accepted_EPS * 86,400 * retained_days * observed_indexed_bytes_per_event`

`required_raw_volume_bytes = raw_event_bytes + raw_segment_metadata + raw_volume_spool_or_backup + raw_volume_headroom`

`required_index_volume_bytes = index_bytes + sqlite_WAL_and_temp + index_volume_backup + index_volume_headroom`

`per_volume_free_required = required_bytes_on_that_volume + max(5 GiB, 10% of data_volume_capacity)`

Each volume must individually pass its capacity/reserve test. If raw and
indexed storage share a device, **add** the role requirements there; if they
are separate, check them independently. Do not double-count raw records as
part of an index amplification estimate. Measure indexed bytes per event
including normalization, source metadata, actual SQLite indexes, and journal
behavior. Optional full-packet payload capture (off by default), backups,
spools and temporary migration space must be itemized explicitly rather than
silently included in multiple terms. Display achievable retention and uncertainty.

## 2. Worked examples (not guarantees)

At 100 accepted EPS and a nominal **2,048-byte serialized record**:

| Retention | Events | Raw bytes (decimal) | Raw GiB | At illustrative 2.0x combined raw+index factor, GiB |
| --- | ---: | ---: | ---: | ---: |
| 1 day | 8,640,000 | 17,694,720,000 | 16.48 | 32.96 |
| 7 days | 60,480,000 | 123,863,040,000 | 115.36 | 230.73 |
| 30 days | 259,200,000 | 530,841,600,000 | 494.43 | 988.86 |

For the 7-day illustration, ~231 GiB is an example **combined** raw and
indexed data footprint if indexing adds another 1x the original footprint.
With distinct local volumes, that could mean ~115 GiB on the raw drive and
~115 GiB on the index drive, **before** each volume's spool, WAL/temp files,
backups and independent free-space reserve. Actual indexed bytes must be
measured; neither volume can borrow unused capacity from the other. A nominal 100 GB disk is insufficient for that
scenario. Lower rates, record sizes, retention, or measured compression can
change this estimate. The benchmark must report actual observed bytes/event
and amplification to revise these figures.

Example W-06 disconnected source: 10 EPS x 1,800 s = 18,000 records;
at 2 KiB each the raw payload is approximately 35.16 MiB before spool
metadata, encryption framing, or filesystem overhead. At higher per-source
rates, a fixed spool limit can fill sooner; quota exhaustion is never silent.

## 2B. Administrator-selectable raw and indexed storage

KnetSentry must let the administrator select a **raw original-event directory**
through a Qt 6/Kirigami filesystem browser. That directory can be on a
**separate mounted local drive**, not necessarily the Ubuntu OS disk. The
indexed-event SQLite database has its own independent directory setting.
System configuration, service credentials and the default audit journal remain
in hardened OS-managed paths unless specifically governed by a separate
approved storage policy. Each role must show where its data actually resides.

**Raw-first contract:** validate source scope and permitted data class, apply
privacy exclusions, then persist an integrity-tagged bounded original event
segment to the approved raw volume *before* normalization and indexing.
Maintain durable stage states and never conflate a persisted raw record with
an indexed record. Sender acknowledgments must state their achieved durability
stage; failed indexes must be replayable from preserved originals. Optional
full-packet payload capture remains **off by default**.

**Mount safety:** store expected filesystem/volume identity as well as
canonical directory. A mount path is not sufficient: if a removable disk is
unmounted, a directory with the same name on the root filesystem could still
exist. Verify mount identity and actual destination before new segments and
on restart/change. Never write there as a fallback. Use daemon-owned,
symlink-safe open/creation and permissions; GUI directory selection alone does
not grant a privileged service access. Mount IDs can be reused and should not
serve as the sole persistent volume identity.

**Failure policy:** missing or changed volume, read-only filesystem, quota or
I/O failure stops raw durable ACK and raises a visible degraded coverage state.
A separately configured, quota-limited and authorized spool may be used only
with administrator opt-in and adequate protection; absent that, fail closed.
No quiet spillover of raw records into an OS-disk directory. Capacity must be
checked **per volume**, including raw records, SQLite WAL/temp/index files,
spools, protected evidence, backup snapshots and reserves. Storage relocation
requires authorization, verified copy/recovery/rollback and audit.

**Supported media:** local, suitably mounted and verified file systems first;
removable drives can be explicitly approved with encryption and loss warnings.
Do not place SQLite WAL databases on unqualified network filesystems. NFS/SMB
and other network-backed raw storage are outside the initial tested v1.0
placement contract unless separately qualified. Report filesystem and device
throughput when benchmarking an external drive, and account for differing
failure and durability behavior.

See [storage placement contract](../architecture/STORAGE_PLACEMENT_CONTRACT.md)
for detailed UI/security/failure responsibilities.

## 3. Memory, CPU and storage budgets

| Process / area | Initial reference target | Scope |
| --- | --- | --- |
| Manager | RSS <= 1536 MiB, average CPU <= 200% of one logical CPU | W-01; manager only, not separate capture or AI processes |
| Capture broker + sensor parser | Combined RSS <= 512 MiB | W-03 after warm-up; each component still instrumented separately |
| Optional agent | RSS <= 256 MiB | Each endpoint; not needed for mandatory agentless path |
| Qt desktop | RSS <= 1024 MiB | W-05 live dashboard and searches |
| Local AI | No fixed v1.0 core budget; optional and independently accounted | Must not mask SIEM resource pressure or disable core function |
| Disk reserve | >= max(5 GiB, 10% data volume) | Before approved data, maintenance and critical event admission |

CPU usage as `200%` refers to the Linux process convention where one fully
busy logical CPU is `100%`; report effective quotas and affinity. Process RSS
is not additive proof of physical memory usage for shared mappings; record
PSS/cgroup totals when possible. Monitor swap, disk throughput, page faults,
filesystem fullness, and Linux CPU/memory/I/O PSI when supported.

## 4. Retention and data protection

- The administrator selects an explicit retention period, with supported
  **24-hour** and **7-day** cases tested when the underlying disk budget fits;
  this document does not force a seven-day default on every installation.
- Apply consistent policy to normalized events, original evidence, indexes,
  sensor spool, and optional raw packet data with separately stated windows.
- Protected incident evidence and administrative holds must not be silently
  pruned by ordinary retention or disk-pressure cleanup.
- Warn at configured capacity thresholds; if quota is exhausted, report
  rejected/lost/uncommitted data accurately and maintain policy boundaries.
- The SQLite transaction/checkpoint/durability mode is an implementation
  decision to benchmark; claiming zero acknowledged loss requires a tested
  acknowledgment point and storage fault model. SQLite WAL `synchronous=NORMAL`
  does not provide the same power-loss durability as `FULL`.

## 5. Dependency and source references

- [SQLite WAL documentation](https://www.sqlite.org/wal.html): checkpoint,
  WAL behavior and durability limitations.
- [SQLite PRAGMA reference](https://www.sqlite.org/pragma.html): synchronous
  options and trade-offs.
- [Linux pressure stall information](https://docs.kernel.org/accounting/psi.html):
  CPU, memory and I/O pressure measurement where enabled.

Storage and process budgets are scoped to
[requirements](PERFORMANCE_REQUIREMENTS.md) and
[workload fixtures](WORKLOAD_PROFILES.md); M6 and M14 will implement and
measure them. Do not represent these planning numbers as device minimums.

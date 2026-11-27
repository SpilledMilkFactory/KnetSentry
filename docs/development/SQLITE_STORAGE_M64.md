<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M6.4 — SQLite Metadata and Indexed Event Storage

Issue #54. Development implementation; Ubuntu maintainer qualification passed (124 gates, 417 CTests, 90 supplementary repeated tests, nine hosted checks, no analysis-build diagnostics). M6.5 extends this historical schema to v3; see [M6.5](EVIDENCE_INTEGRITY_M65.md) for the integrity contract; [M6.6](EVENT_SEARCH_M66.md) extends the schema to v4.

## Backend and trust boundary

`KnetSentry::SqliteStorage` implements the existing `EventStore` contract via
`SqliteEventStore`. The existing memory reference and ReceiptSink remain
unchanged. The caller must select an existing dedicated private local directory
with trusted stable ancestors. No default path, directory creation, automatic
fallback, operational manager adapter, new privileges, network, or GUI query
service is provided. The backend holds a cooperative exclusive directory flock.
It validates the absolute non-traversing path with Linux openat2, rejects
symlinks, validates owner and exact 0700 directory / 0600 single-link regular
file permissions, rejects WAL/SHM, checks rollback-journal safety, and checks
directory and database device/inode identity before operations. Supported
filesystem magic values are ext4-family, XFS, Btrfs, F2FS and overlay (development
only). These checks are not production volume authorization: they do not
establish persistent expected mount UUID across restart, protection against
hostile same-UID writers, ancestor/rename races during SQLite operations,
or underlying media durability. Overlay is not qualified for deployment.

SQLite's filename NOFOLLOW flag is used with the checked absolute path; it
rejects proc-fd symlinks. The descriptor is retained for identity checks, not a
claim that SQLite's VFS is descriptor-relative. No direct database access by
other processes is supported except controlled negative-test fixtures.

## Persistence and migration

The fixed file is `events-m64.sqlite3`. Empty schema version 0 initializes
strict tables with a fixed application ID, then migrates to version 2. Version
1 represents the same tables without secondary indexes; the known v1 -> v2
migration adds search, binding and retention indexes. No prior production v1
release exists. Schema creation, migration and validation are transactional.
Unrecognized application IDs, schema versions, unexpected schema objects,
invalid persisted records, or inconsistent indexed projections reject opening.
SQLite integrity_check runs on activation. Stored mapping pin is OCSF 1.4.0,
KnetSentry mapping revision 1. Raw canonical bytes and receipt time remain
unchanged on retry; monotonic storage IDs and revisions survive restart.

Every mutation uses a transaction; success is reported only after COMMIT.
DELETE rollback journaling and synchronous=EXTRA are selected and checked;
SQLite uses memory for temporary storage, disables extension loading, attached
databases and trusted schema, and enables defensive mode. The connection is
private to the backend. Values are bound parameters, never SQL fragments.
Database page size is 4096 and maximum page count 2048 (8 MiB main file; not a
complete disk budget). Busy timeout is 100 ms; filesystem I/O itself is not
bounded by it. `secure_delete=ON` is best effort, not a secure erasure claim.

The SQLite store reports durable transaction capability, conditional on the
filesystem and SQLite/VFS honoring their sync contract. It does not implement
ReceiptSink and cannot authorize an authenticated ACK. The development database
contains minimized original evidence and indexed fields in the same table;
raw admission and index publication are separate transactions. Original
raw-volume segments and independently configured index placement are future
work, not superseded by this database. The existing receipt implementation
remains authoritative for authenticated delivery. Power loss, ENOSPC/EIO,
quota, crash-at-arbitrary-instruction and multi-volume recovery are not fully
qualified by the tests.

## Query, retention and enum correction

The M6.3 limits remain 128 records, 2048 canonical bytes per record, and 32
records/IDs per page or retention plan. Typed queries select indexed records
only; normalized summaries are checked by recomputing the pinned projection.
Pending evidence is replayable through explicit index operations. Retention
uses trusted caller receipt time and excludes held and pending records.
Revision-checked plans are revalidated in a transaction before deletion.
Exact retries preserve receipt time and hold; conflicts never overwrite.
IDs and revisions are database-scoped, not authorization tokens. Deleted
records have no tombstones. Corrupt data is rejected on activation; continuous
hostile on-disk tamper detection and signed evidence remain future work.

The M6.3 maintainer analysis log reported `EnumCastOutOfRange` from the deliberate
`static_cast<J>(99)` negative normalization fixture. M6.4 introduces a named
Unsupported mode and checked integer decoding, retaining the rejection test and
rejecting unknown SQLite mode values before interpreting them as supported
collection modes. Stored classification integers are compared against the
canonical typed projection, not cast to enums. The native journal source also
rejects unsupported modes before opening the source. Clang analyzer warnings
are promoted to errors in the first-party clang-tidy configuration.

## Dependency review and qualification

DEP-006 is approved for this development build only: maintained distro shared
SQLite >= 3.37 (`libsqlite3-dev`, `libsqlite3-0`). No vendored SQLite code or
extensions are distributed. SQLite core upstream is public domain; distro
packaging and any other bundled components require separate review of actual
package notices. Record exact Ubuntu package versions in CI and acceptance;
this is not release redistribution clearance. Upstream references:
[SQLite copyright](https://www.sqlite.org/copyright.html),
[connection flags](https://www.sqlite.org/c3ref/open.html), and
[PRAGMA reference](https://www.sqlite.org/pragma.html).

`knetsentry_sqlite_storage_contract` exercises real SQLite using disposable
0700 synthetic directories on a supported filesystem in /var/tmp, with no host
telemetry. It covers restart, known migration, future schema refusal, failed
commit rollback, interrupted uncommitted SQLite write recovery, holds, pending replay, search pagination, retention, capacity,
invalid stored mode and projection rejection, and unsafe path/permission cases.
Target desktop counts 64/58, core-only 51/52 (normal/sanitized), 417 CTest
executions, 56 structural verifiers, 124 consolidated acceptance gates.
No production deployment, threat closure, or independent security audit is
claimed. Issues #40/#46/#50/#51 remain outstanding. Issue #54 production
independent raw/index placement and manager integration remain outstanding.

M6.7 makes the existing main database page ceiling configurable downward,
without a schema change. See [retention and quotas](STORAGE_RETENTION_M67.md).

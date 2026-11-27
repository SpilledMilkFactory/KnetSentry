<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M6.3 — Event storage abstraction

Issue #53 defines stable persistence, retrieval, search and retention interfaces
independent of the database implementation. This increment supplies C-13's
GUI-independent C++ contract and a bounded, executable volatile reference
backend. See the [storage placement contract](../architecture/STORAGE_PLACEMENT_CONTRACT.md)
and [M6.2 normalization](EVENT_NORMALIZATION_M62.md).

## Interface and ordered state

`include/knetsentry/storage/event_store.hpp` defines `EventStore`, implemented
by `MemoryEventStore` in `src/agent/event_store.cpp`, built as
`KnetSentry::EventStorage`. The interface is independent of Qt and SQLite.
All methods are serialized by one trusted service owner. No operational caller,
network listener, filesystem path, database, credentials or GUI model is added.

| Interface | Semantics |
| --- | --- |
| `append` | Validate canonical minimized KSTD evidence and configured source; assign a backend-scoped ID and preserve exact original bytes and trusted receipt time. |
| `index` | Reapply the pinned normalizer to stored original evidence; publish typed projection only on success. |
| `raw` / `normalized` | Return independently owned copies; distinguish missing evidence, pending index and success. |
| `pending` | Enumerate IDs awaiting indexing in bounded revision-checked pages. |
| `search` | Return bounded indexed summaries with typed filters and explicit continuation. |
| `set_hold` | Explicit reference hold or release, never an authorization or legal-hold service. |
| `preview_retention` / `apply_retention` | Compute and validate a bounded explicit deletion plan; exclude pending and held evidence. |

The reference backend implements a raw-first *ordering model*, not durable
persistence. Append and index return typed status and durability independently.
Only `Volatile` is returned on reference success, including exact retries; all
rejections return `None`. `Durable` is reserved for future qualified backends.
The reference backend is not a `ReceiptSink`, is never used in authenticated
acknowledgment processing, and cannot claim `RAW_DURABLE` or durable `INDEXED`.
Existing M5.5/M6.1/M6.2 receipt processing is unchanged. An operational adapter
must require actual durable raw commitment before ACK, independently of index
success. Normalized data is reproducible from the pinned mapping, not from
caller-supplied classification or modified source bytes.

## Validation and identity

Append uses the same bounded canonical parser as ingestion, validates exact
configured binding, source unit and mode, and requires positive receiver time
in signed 64-bit millisecond range. Authorization, consent, current enrollment,
privacy permits and trusted receipt-clock acquisition remain caller duties.
Receipt time is supplied by the trusted caller, not derived from the source
clock. Original realtime and monotonic microseconds and OCSF mapping revision
remain preserved in the normalized value. No raw journal message is recreated.

The first 32 binding characters (configured endpoint identity) and native
cursor are the reference deduplication key. Exact retries preserve the assigned
ID, original receipt time, hold and index state. Any changed canonical bytes,
source profile or manager binding for an existing key are conflicts; another
endpoint can independently use the same cursor. No overwrite or implicit
eviction is permitted. IDs are positive, increasing, not reused within one
backend lifetime; ID/revision exhaustion fails without wraparound. The signed
64-bit ceiling avoids relying on unsigned overflow for future SQL integration.

## Search and pending enumeration

Search filters by exact configured binding (empty means all authorized by the
trusted caller), OCSF class, OCSF status and inclusive normalized source-time
range. Fixed enums and filter bounds are validated; no query language or SQL
text is accepted. Summaries carry ID, source/receipt milliseconds, typed class,
activity, status and mapping result, not original row bytes. Explicit `raw` and
`normalized` reads remain sensitive and are not access-control APIs.

Search and pending IDs are ordered by increasing storage ID, not source time.
A continuation uses the last returned ID and exact revision from the preceding
page; all mutations invalidate prior revisions. A stale page must be restarted,
not silently continued. The caller must preserve query filters and use cursors
and retention plans only with the same backend instance. Neither revision nor
ID is a security token. Caller-held results are snapshots; no persistent cursor
or cross-restart guarantee is made.

## Limits and retention

- At most 128 live reference records, each with at most 2,048 canonical bytes
  (256 KiB canonical originals, excluding strings, projections and container
  overhead). The memory cap is a record-count model, not an RSS guarantee.
- Search, pending and retention plans return at most 32 records/IDs per call.
- A full store rejects new records; exact existing retries remain possible.
- Explicit retention uses **receiver** milliseconds, strictly older than the
  supplied cutoff. The oldest eligible storage IDs are selected first, not a
  claim of chronological sorting. Pending and held evidence is excluded.
- Apply recomputes the candidate IDs against the current revision, cutoff and
  limit; stale or mismatched plans cannot remove evidence. Raw and normalized
  views are removed together. There is no background purge, time-based trigger
  or automatic capacity eviction. Releasing a hold is an explicit trusted
  operation and changes the revision.
- Retention does not retain tombstones; a previously deleted cursor can be
  re-admitted with a fresh ID. Persistent deduplication horizon, legal-hold
  policy, retention audit, quotas, secure deletion and backups are future work.
- The backend may propagate allocation failure. Mutations allocate/validate
  before publication and use nonthrowing moves for index/entry updates. Search
  copies and caller-held evidence require independent resource limits.

## Qualification and remaining scope

`knetsentry_event_storage_contract` exercises the interface through a base
reference using synthetic metadata, authentication, redacted and audit rows.
It covers raw-before-index visibility, original ownership, endpoint-scoped
retry/conflict, invalid inputs, typed search, pending pagination, stale
revisions, explicit hold, tampered/stale retention plans, strict receiver-time
cutoff, bounded capacity, missing records and absence of restart durability.
The reference backend has no filesystem or database operations.

Target: desktop 63/57, core-only 50/51 (normal/sanitized), 410 CTest executions,
55 structural verifiers, 121 consolidated acceptance gates. Target-host
qualification passed (121/0/0/0; 410 CTest executions; nine hosted checks; 75 supplementary repeated tests). M6.4 resolves the analyzer enum warning from the M6.2 negative fixture. M6.4 SQLite and M6.5 original-event integrity work
remain distinct. M0.5 stable destination identity, service permissions,
mount safety, approved secondary volumes and no-silent-fallback requirements
remain outstanding, as do raw segment durability, independent index placement,
crash recovery and migration. No production store, full TB-07 qualification,
operational ingestion, end-to-end authorization or threat closure is claimed.

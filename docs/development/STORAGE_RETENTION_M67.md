<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M6.7 — Retention, storage quotas and cleanup

Issue #57. Development storage policy; maintainer qualification and merge reported successful (130 PASS, all 438 configured CTest executions, nine hosted checks). See [project status](../PROJECT_STATUS.md) for the accepted evidence.

## Configuration and limits

The serialized trusted owner supplies an immutable `StoragePolicy` at backend
construction. No policy is loaded from untrusted database contents. The owner
must explicitly reapply its approved configuration after restart; no policy
persistence, config-file parser, scheduler, GUI or operational manager adapter
is introduced. Invalid policies throw before SQLite activation.

| Policy | Default | Accepted range |
| --- | ---: | ---: |
| Record limit | 128 | 1–128 |
| Canonical wire-byte limit | 262144 | 1–262144 |
| SQLite main-file page limit | 2048 | 16–2048 |
| Warning threshold (percent) | 80 | 1–100 |
| Retention age (ms) | 0 (disabled) | 0–INT64_MAX |
| Cleanup batch | 32 | 1–32 |

The page size remains 4096 bytes. SQLite enforces `max_page_count` on the
connection and refuses activation if an existing database exceeds the requested
page limit. A small quota may also be insufficient for schema initialization or
migration; failure refuses activation, without deleting evidence. Schema v4,
existing original commitments and legacy migration authorization remain unchanged.

Record and wire-byte quotas count all retained originals including held and
pending records. Wire bytes include exact canonical payload bytes, not indexes,
allocation overhead, credentials or raw journal messages. Admission checks the
projected count/bytes after validating input and checking exact retry/conflict.
Exact retries remain available at quota. Quota refusal returns Capacity without
an ID, durability claim, deletion or revision change. Reopening with a lower
logical quota preserves existing records but refuses new ones until capacity
permits. SQLite may independently refuse append/index with Capacity when page
allocation fails; failed transactions roll back. No implicit fallback or eviction.

## Warnings

`usage()` returns typed aggregate counts of retained records, canonical wire
bytes, held and pending records, plus record/byte warning flags. The flags use
`used >= ceil(limit * warning_percent / 100)`; they are observations, not deletion
permissions. SQLite additionally reports allocated and reusable (freelist) pages
and an allocated-page warning using the same threshold. The volatile reference
backend reports no disk metric. Valid SQLite usage requests verify schema and
all original-evidence commitments within a transaction before returning counts.
Failed queries return a typed failure without a usage snapshot.

The main-file limit is NOT a total directory/filesystem quota. Rollback journals,
filesystem allocation metadata, backups and unrelated files consume additional
space. No filesystem reserve or available-space guarantee is claimed. Allocated
page count is not physical block consumption; deleting records generally frees
pages for internal reuse without shrinking the file. Warning flags may remain
set after cleanup. No VACUUM, truncation, unlink, or physical secure-erasure
claim. Production volume quota/reserve and authenticated warning delivery remain open.

## Explicit cleanup

`preview_cleanup(now_ms)` uses the trusted caller's receiver-clock snapshot and
configured retention age to compute an exclusive cutoff (`received_ms < cutoff`).
Zero age disables the policy path; zero/unsupported clock values reject; an age
at least as large as the clock yields cutoff 1 (no eligible valid receipt).
Source-reported timestamps cannot select deletion. Only indexed unheld records
are eligible, ordered by ascending storage ID, up to the configured batch limit.
Preview never deletes. `apply_cleanup(now_ms, plan)` requires explicit trusted
caller approval, the same clock snapshot/cutoff and exact revision, limit and ID
list. The existing backend retention operation revalidates eligibility and
revision within its mutation transaction. Mutation makes earlier plans stale.
An empty valid plan does not advance revision. SQLite removes original records,
normalized projections and integrity commitments atomically; failures preserve
committed state. No automatic age-based or pressure-triggered deletion occurs.
The preexisting `preview_retention`/`apply_retention` methods remain low-level
trusted explicit-cutoff interfaces for compatibility; the policy API is not an
authorization boundary and callers must not expose either interface directly.

No new storage/service authority is introduced; no policy-based cleanup can be
triggered by untrusted LAN traffic. Deduplication after deletion is limited to
retained evidence, as before. Production legal holds, authorization, deletion
audit history, protected external integrity anchors, filesystem quotas and
independent raw/index volumes remain future operational requirements.

## Qualification

`knetsentry_storage_retention_contract` uses disposable synthetic data and both
backends: invalid policy, default disabled cleanup, exact thresholds, logical
quota pressure, exact retry, hold/pending/cutoff protection, forged/stale plans,
monotonic identifiers, reduced quota on reopen, byte quota recovery, real SQLite
page quota with rollback and restart, cleanup commit refusal and retry, freelist
reuse, and tampered evidence refusal. No real telemetry or privileged runtime
access is needed. All existing M6.2–M6.6 regressions remain mandatory.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M7.5 — Rule scheduling, state and suppression

Issue #64, initial caller-driven scheduling foundation for one validated M7.2
native authentication predicate, one explicitly approved store identity, one
full endpoint binding and one exact authentication unit per state directory.
No service, worker thread, timer, GUI, AI, live ingestion or alert publisher
is activated. M7.3 sequence rules and M7.4 Audit rules remain independent
snapshot evaluators; their scheduling adapters are outstanding.

## Interface and deterministic policy

`initialize_schedule` explicitly creates a generation-zero checkpoint. No
implicit initialization, reset, migration or alternate location is allowed.
`run_schedule` takes an authorized EventStore, caller-supplied trusted receiver
clock in milliseconds, explicit enabled flag, evidence trust and coverage.
`acknowledge_schedule` clears only the exact pending generation. The caller
must establish authorization, keep a stable unique 64-hex store identity
(not derived from endpoint identity), serialize store access and supply the
same policy on restart. Store tokens are not credentials; never reuse a token
for a restored, replaced or unrelated database. Use durable stores outside
synthetic fixtures. Configuration is explicit on each call, not read from
untrusted external rule files. One directory per rule/policy/store scope.

- Validate the M7.2 rule and require its exact authentication unit, nonzero
  interval/window at most 24 hours, suppression 0–24 hours, threshold 1–16.
- Disabled and unverified calls do not open state or query evidence. An enabled
  call before the interval elapses returns NotDue unless a batch is pending.
- First tick is immediately due; subsequent ticks use elapsed time since the
  last successful scan. No catch-up loop. Clock regression is refused.
- Scan the retained snapshot in increasing admission-ID order, at most four
  pages of 32 and 128 records. Enforce exact source, revision consistency,
  monotonic receiver times, no future receipts, unique increasing IDs and no
  pending index records anywhere in the selected store. The trusted storage
  backend enforces the binding selector. Validate retained old summaries and
  verify that each carried context ID still exists and matches the rule.
- A persisted high-water admission ID excludes already processed observations.
  Expire observations older than `window_ms` at tick time (inclusive boundary).
  Match only definite M7.1 findings. Keep at most the latest threshold matching
  IDs and receiver times across ticks, not actor identity or a sequence rule.
  Unknown/redacted/nonmatching observations do not contribute to the count.
- At threshold, emit a candidate with the ordered supporting IDs, unless its
  receiver time is within `suppression_ms` of the last emitted candidate.
  Zero suppression disables that check. Equality at the suppression boundary
  permits a candidate. Suppression still advances the checkpoint and context;
  it never modifies or deletes stored evidence. Findings have rule identity,
  version, configured severity and schedule identity on their report. Coverage
  is conservatively reduced when carrying context from an earlier scan.
- Refuse malformed/stale pages, missing live context, pending indexes, clock
  regressions and store failures without publishing partial results or advancing
  the committed checkpoint. Allocation/cryptographic exceptions propagate;
  never interpret refusal as a successful negative result.

## State and delivery boundary

Existing private-state path helpers enforce absolute non-symlink components,
non-root owner, mode 0700 directory, supported local filesystem, nonblocking
exclusive directory lock, and regular single-link owner-only mode 0600 files.
The caller must approve and protect the directory and its ancestors and ensure
stable mount identity. This is not the M6.10 persistent volume-approval system.
State contains a SHA-256 policy binding (including the validated rule metadata,
store token, endpoint, exact source and scheduling parameters), numeric IDs,
receiver times, counters, coverage, generation, revision, bounded context and
at most 128 pending candidates with at most 16 IDs each. The file is capped at
256 KiB; exact canonical parsing and a SHA-256 checksum reject malformed and
accidentally corrupted state. This is neither encryption nor an authenticated
anti-rollback commitment against a malicious state owner.

Writes create an exclusive private pending file, sync it, rename it over the
checkpoint and sync the directory. A valid committed checkpoint may discard
an abandoned private regular pending file; unsafe pending objects refuse.
An interrupted initialization with no committed checkpoint requires explicit
operator review. A failed sync can leave an uncertain commit; the caller must
retry and inspect the committed state rather than assuming failure erased it.
No candidate is returned until the write succeeds. A committed nonempty batch
is returned as Replay on later enabled, trusted calls before any new scan.
The replay is the historical generation, not a new verified snapshot. The
caller must reverify referenced evidence and current authorization before use
and durably deduplicate by `(schedule_identity, generation, trigger ID)` before
acknowledging. A wrong or already acknowledged generation is refused. The
acknowledgement transaction does not delete original evidence. Exactly-once
external publication, evidence holds and cross-store transactions are not
provided. The caller must not acknowledge an unconsumed generation.

## Verification and remaining scope

`knetsentry_scheduler_contract` uses synthetic reference and real SQLite
stores, a separate child process committing a candidate before restart,
explicit state initialization, persistent correlation, replay/acknowledgement,
interval and enablement, suppression boundary, pending refusal, file modes,
lock contention, unsafe pending objects, corruption, retained-context deletion,
expiry, actual child-local file-write exhaustion, malformed later-page refusal and 128-record pagination. No private telemetry is needed.

M7.5 is a foundation, not unattended operational rule scheduling. Keep #64
open for scheduling adapters for M7.3/M7.4, durable alert consumer integration,
operational scheduler lifecycle and production authorization/volume binding.
Issue #63's remaining FIM evidence and confirmed integrity semantics remain
open. Target Ubuntu qualification is pending.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M7.6 — Alert creation and lifecycle management

Issue #65 implements a caller-driven, private alert ledger for one validated
M7.5 schedule scope. No GUI, operational scheduler, listener, response action,
AI or alert service is started. The backend is separate from original evidence.

## Identity and consumption

Explicitly initialize a separate approved private directory with
`initialize_alerts`. `consume_alerts` reads the actual committed pending
scheduler generation, not a caller-supplied finding list. Require caller
established authorization, verified stored evidence, a durable EventStore,
trusted time, stable store identity and serialized access to scheduler, alert
and evidence stores. These caller assertions are not authentication; production
roles, mount identity and transport integration remain outstanding.

The stable alert key is (schedule identity, generation, triggering event ID).
The versioned ledger stores the schedule commitment, store identity, endpoint
binding, exact unit, rule ID, rule version and configured rule severity. Each
alert records snapshot revision, conservative coverage, creation and update
receiver-clock timestamps, and ordered evidence IDs with source and receiver
timestamps and evidence SHA-256 and integrity origin. For every candidate,
read raw and normalized evidence through the trusted storage interface, verify
binding, unit, collector mode, ordered IDs, receiver window and rule match.
Require an integrity digest and no pending index entries; check revision again
before committing. No raw rows are copied to alerts. Source time is provenance,
not trusted scheduling time. LegacyBaseline integrity is not admission proof.

Commit the entire candidate generation in one bounded transaction. Replay must
match the complete existing generation including immutable evidence and coverage;
return ExactRetry without changing lifecycle metadata. Only after Ok or ExactRetry
may a serialized trusted caller acknowledge that exact scheduler generation.
An uncertain commit requires retry/inspection, never an automatic ACK. Missing,
changed or unavailable evidence prevents consumption (including replay). Existing
alerts remain historical references even when retention removes evidence; they do
not prove that the evidence remains available. No holds or cross-store atomicity
are introduced; evidence-retention coordination remains a follow-up.

## Lifecycle and limits

`read_alerts` exposes a bounded private snapshot, not a public endpoint.
`update_alert` requires the stable key, current revision, authorized analyst
identifier and trusted non-regressing update time. Allowed transitions are
Open -> Acknowledged -> Resolved. Notes may be appended at any status, including
Resolved; acknowledgement and resolution preserve their time and actor. No
reopen, delete, severity rewrite or note edit is supported. Each successful
mutation increments revision, so stale writes are refused. IDs and original
evidence are never mutated. Resolution is analyst disposition, not remediation.
Analyst identifiers are 1–64 ASCII letters, digits, dot, underscore or hyphen;
notes are 1–256 printable ASCII bytes, max eight per alert. Render as plain text
in any future GUI; do not enter credentials or private raw telemetry. Notes are
sensitive plaintext at rest, never logged by this backend. Limit 128 alerts,
16 evidence IDs per alert and 256 KiB total serialized state. At capacity refuse
without evicting or acknowledging findings. Production pagination, archival,
retention and note privacy policy are future work.

## Filesystem and integrity

Use existing private-state helpers: non-root, absolute non-symlink directory,
supported local filesystem, owner 0700 directory, nonblocking exclusive lock,
owner 0600 regular single-link files. The caller must approve stable directory
and mount identities and protect ancestors. Explicit initialization only;
no fallback or reset. Canonical versioned state and SHA-256 detect corruption,
not malicious owner rollback/rewrite. Exclusive temporary creation, fsync,
rename and directory fsync commit the entire ledger. Recover a regular private
abandoned pending file only after committed state validates. A failed sync may
leave uncertain state; retry under the same scope. Allocation/crypto failures
may propagate; do not interpret them as negative detections or successful writes.

## Verification and scope

`knetsentry_alerts_contract` composes actual SQLite and M7.5 state using synthetic
fixtures, a separate child process committing before restart, replay and ACK,
optimistic lifecycle revisions, bounded notes, scope and permission refusal,
unsafe pending object, hard-link, lock and corruption refusal, actual child-local
file-write failure and retry, missing evidence and original-evidence invariance.
Multi-candidate atomic publication and later evidence failure refusal are also tested.
No actual host telemetry or privileged changes are needed. Target qualification
pending. Issue #65 remains open for production authorization, retention/holds,
multi-scope alert service, and integration of remaining detection families.
Issues #63 and #64 retain their documented outstanding scope.

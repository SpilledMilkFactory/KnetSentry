<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M6.9 — Ingestion, storage and recovery regression tests

Issue #59. Regression-only qualification of the bounded M6.1–M6.8
foundations. No production code, storage schema, dependency, transport
permission, GUI behavior or service configuration is changed.

## Failure matrix

| Scenario | Actual test mechanism | Required result |
| --- | --- | --- |
| Malformed input and timestamps | Both EventStore implementations, invalid canonical rows, noncanonical/overflow source time and invalid receiver time | Invalid; no ID, durability or revision mutation |
| Source-time anomaly | Valid 1-us and maximum supported source timestamp; source order reversed relative to receiver order | Exact provenance preserved; millisecond truncation explicit; inclusive source-time filtering and receiver-time retention |
| Duplicate or conflicting record | Both backends, changed receiver time and conflicting source timestamp for same endpoint/cursor | Exact retry preserves original ID, receiver time and revision; conflict refused |
| Writer contention | Real competing SQLite BEGIN IMMEDIATE | Append and indexing refused; state and revision unchanged after lock release |
| Interrupted writes | External fixture transaction modifies hold and metadata, flushes dirty pages, checks rollback journal magic, then SIGKILLs itself | Reopening the real EventStore restores committed evidence, integrity digest, hold, pending state and revision |
| File-write failure | Separate child lowers RLIMIT_FSIZE soft limit to zero after activation and ignores SIGXFSZ | Production append returns IoError or Capacity, no ID or durability; restart retains committed state |
| Interrupted migration | Populated v3 fixture constructed by removing v4 indexes; competing reader blocks activation/migration | v3 and its original index set remain intact; retry reaches v4 with unchanged evidence/digest/revision |
| Page allocation exhaustion | Actual SQLite 16-page max_page_count using bounded padded canonical records | Capacity, no partial admission, bounded allocated pages, exact retry and restart preserve records |
| Authenticated malformed receipt | Actual in-memory mutually authenticated TLS, production receiver and pipeline | Invalid before test sink invocation; no normalized event or ACK |
| Authenticated storage refusal | Test-only receipt adapter uses actual SqliteEventStore, unsafe directory permissions, conflicting duplicate and record quota | Failed TLS receiver, no normalized event or acknowledged disposition, released admission slot |
| Authenticated retry/restart | Reopen the same store and replay exact canonical record | Original ID/receiver time and pending index survive; actual TLS ACK digest matches payload; explicit index publication after restart |

## Test boundaries

`knetsentry_storage_recovery_contract` runs a standalone native executable.
`knetsentry_ingestion_recovery_contract` invokes the existing enrollment/TLS
fixture executable with `--ingestion-recovery`. The test-only ReceiptSink
adapter accepts only durable Ok/ExactRetry append outcomes and supplies a
fixed synthetic receiver clock. It is not linked to production ingress.
The real production ReceiptSink remains the delivery acknowledgment boundary.
Both tests run in all seven presets, including core-only and sanitizer builds.
No production receipt-to-store integration or authenticated operational listener
is implied.

All databases are private mkdtemp fixtures under `/var/tmp`; enrollment fixture
credentials are generated in memory. The subprocess file limit does not affect
the parent or the host filesystem. The hot-journal test interrupts an external
SQLite transaction after cache flush, not a precisely selected production
append instruction. The test does not simulate sudden power loss, kernel or
storage-controller failure, host ENOSPC, independent volume quotas or physical
secure erasure. SQLite/OpenSSL shared library code is not necessarily sanitizer
instrumented. Corruption, rollback and recovery guarantees remain bounded by the
existing development architecture and integrity model.

Run as an ordinary user:

```bash
ctest --preset linux-release -R '^knetsentry_(storage_recovery_contract|ingestion_recovery_contract)$' --verbose --no-tests=error
```

Maintain preceding ingestion, delivery, normalization, storage, integrity,
search, retention and explorer regressions. The official Ubuntu matrix, analyzer,
GUI non-regression, installed-systemd checks and hosted CI remain maintainer
acceptance gates. Do not treat structural registration as runtime evidence.

## Maintainer acceptance

M6.9 was qualified and merged on 2026-11-27: 134 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED; 470 configured CTest executions; 130 repeated Release and 65 repeated sanitized executions; clean analysis diagnostics and nine green hosted checks. Manual GUI review was reported successful.

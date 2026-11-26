<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M5.8 — Collector verification and failure recovery

Issue #49 qualifies representative failure behavior of the existing C-08/P-08
collector and offline delivery foundations. No production source, policy,
privilege, persistent format or network behavior changes in this issue.

## Required regressions

`knetsentry_collector_recovery_contract` runs the real JournalCollector and
protected persistence implementation with an injected, deterministic source.
It exercises four profiles (journal metadata, classified authentication,
redacted authentication, audit), each with local-only and buffered storage,
using synthetic identifiers and a synthetic policy fingerprint. The test does
not exercise the CLI policy parser directly; the existing M5.7 actual-agent
and native authentication regressions remain required.

| Fault | Expected invariant |
| --- | --- |
| Source read error after valid prefix | Retain each successfully committed record; no further reads until restart |
| Malformed or nonadjacent duplicate record | Reject on every retry; do not consume later records or advance committed checkpoint |
| Duplicate persisted record | Reject before source open; no state mutation |
| Insecure state-file mode | Reject before source open |
| Runtime directory mode change | Stop before consuming source records |
| Pending-file collision after startup | Failed transaction leaves committed state and colliding file intact |
| Pending symbolic link | Reject before source open; leave link and target intact |
| Safe abandoned pending file | Discard uncommitted file, resume exactly after committed cursor |
| Stale checkpoint or unavailable source | Local store startup fails; buffered store retains records with collection blocked |
| SIGKILL after committed batch | Release lock by process exit, preserve committed records, recover on restart |
| Disconnected full queue | Repeated pumps and restart consume no additional source record |

The crash test synchronizes at a known durable boundary with SIGSTOP, then
uses SIGKILL on its own disposable child. The child creates a synthetic pending
file before stopping; this models an abandoned transaction without claiming
that a real write, rename or fsync was interrupted. No actual host process or
journal is involved. The test uses CTest's bounded timeout.

The existing `knetsentry_telemetry_delivery_contract` additionally exercises
real mutually authenticated TLS sessions with deliberate exclusive-create
collisions in the actual receiver inbox and sender outbox. Receipt failure
must not acknowledge or dequeue; after restart, a valid receiver commit
followed by sender ACK persistence failure must leave the record retryable.
A fresh retry is accepted idempotently and the successful ACK durably advances
the sender, retaining its checkpoint even when empty. Existing lost-ACK,
revocation, malformed-frame, timeout and capacity tests remain mandatory.

## Verification procedure

Run as an ordinary user from the repository root, after a Release build:

```bash
ctest --preset linux-release -R '^knetsentry_(collector_recovery_contract|telemetry_delivery_contract)$' --verbose --no-tests=error
```

All seven presets register the recovery test and retain existing native journal,
authentication, audit, actual-agent FIM, privacy, lifecycle and TLS regressions.
The local acceptance runner remains untracked. Synthetic fixture state is
created under private temporary directories and removed by the test harness.
No real host telemetry, credentials, files, privileges or network sockets are
needed for the new regressions.

## M5.8 follow-up qualification

The initial Ubuntu 26.04 acceptance run reported 108 PASS, 1 FAIL, 4 SKIPPED,
and 0 BLOCKED. All 314 executed CTests passed; Clazy rejected two namespace-scope
`std::string` fixture identifiers under `clazy-non-pod-global-static`.
The follow-up replaces them with constant-initialized character arrays and
compile-time length checks, preserving the exact synthetic identifier bytes.
No recovery assertions, compiler diagnostics, or privileged acceptance gates
are disabled. The four dependent checks were skipped, not failed at runtime.
Corrected maintainer acceptance passed (113 PASS, 0 FAIL, 0 SKIPPED,
0 BLOCKED; 371 configured CTest executions). Direct recovery, 20 repeated
Release and 10 repeated sanitized executions, manager binary comparison,
reported manual GUI verification and nine hosted checks (`d6677a5`) passed;
the maintainer reported merge.

## Boundaries

These are representative deterministic fault cases, not exhaustive fault
injection, ENOSPC/EIO testing, hardware power-loss durability, adversarial
same-UID tamper resistance or proof of lossless journal rotation. FIM has an
in-memory baseline and cannot recover changes while stopped. Receiver policy
administration and operational agent-to-manager delivery (#46) and remaining
M4.7 operational enrollment (#40) are outstanding. TB-06/TB-07, TV-13/TV-26 and
TB-04/TV-06/TV-07 gain partial evidence; no threat is closed. No new dependency
or licensing scope is introduced. Target-host and hosted qualification are
required before issue acceptance.

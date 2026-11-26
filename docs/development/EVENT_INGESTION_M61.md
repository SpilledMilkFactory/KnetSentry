<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M6.1 — Bounded authenticated event ingestion

## Scope and interfaces

This increment introduces the Qt-independent `IngestionPipeline` in the existing
AgentDelivery library, a partial C-11 / I-08 boundary for KSTD telemetry. It is
exercised using genuine mutually authenticated TLS and the existing durable
receipt sink. It does not deploy a manager listener or implement the generic
I-04/I-06 source adapters or I-10 normalization interface. No remote transport,
monitoring permission, new dependency, schema migration or host privilege is
introduced. Issues #40, #46 and #50 remain outstanding.

The trusted caller configures one pipeline per endpoint, manager fingerprint,
exact journal source and record mode (metadata, authentication or audit), and
supplies its durable `ReceiptSink`. The receiver now takes that pipeline rather
than independently selecting its source and sink. Configuration values are
not taken from the peer. The caller must select the appropriate approved
source, local TLS credentials and sink, and supply current network authorization.
The existing enrollment registry revalidates the authenticated peer on each
receiver step and again after a successful commitment before ACK transmission.
Authentication establishes peer identity, not truth of reported observations.
Receiver policy distribution and independent privacy approval remain outstanding.

## Pipeline and resource bounds

1. Revalidate TLS protocol, caller authorization and current enrollment.
2. Reject invalid pipeline configuration; enforce the existing five-second
   caller-driven exchange deadline.
3. Reserve one of four in-flight slots **per pipeline**, before reading event
   plaintext. If all slots are occupied, abort the new exchange without reading
   its application payload or invoking the sink. No unbounded waiting queue.
4. Receive one bounded KSTD record (8-byte header, 2144-byte body maximum;
   96-byte destination binding plus at most 2048 bytes of canonical row).
5. Verify exact binding and canonical row shape, configured source/mode,
   bounded identifiers and timestamps using the established journal validator.
6. Dispatch synchronously to the existing bounded durable sink. No raw invalid
   event quarantine is created. A sink refusal aborts without ACK.
7. On durable acceptance, revalidate enrollment before sending the existing
   digest ACK. Complete or abort and release the slot. Abandoned receivers
   release their slot on destruction.

The pipeline is single-owner, serialized and nonreentrant; the sink and pipeline
must outlive all receivers. It contains no worker thread or dynamic event queue.
The cap bounds admitted exchanges, not construction of TLS sessions, OS sockets,
file descriptors or pipelines. The future transport scheduler must enforce global
connection, handshake, per-peer and rate budgets and drive deadlines even if no
input arrives. The synchronous sink may block on filesystem I/O; this milestone
claims neither a real-time I/O deadline nor cross-thread safety.

## Dispositions and recovery

| Outcome | Meaning |
| --- | --- |
| Unauthorized | Wrong protocol, missing authorization or enrollment failure |
| Invalid | Invalid configuration, framing, binding or canonical row |
| Overloaded | No admission slot; retry via fresh authorized connection |
| StorageRejected | Sink refused (capacity, conflict, transaction failure or other refusal) |
| TransportFailed | I/O, deadline, digest or internal exception failure |
| Abandoned | Admitted receiver destroyed before completion |
| Committed | Sink reported durable acceptance, including an exact retry |
| Acknowledged | ACK accepted by local TLS write, not proof of sender receipt |

The pipeline maintains saturating in-memory aggregate counters for these fixed
outcomes. A committed exchange can later fail authorization or ACK transmission;
commit and terminal outcome counts are independent. No raw payload, credential,
path or identity is logged. Counters are neither persistent nor published to GUI.
The sink remains authoritative for exact retry deduplication, conflict rejection,
128-row/256-KiB protected inbox limits and durable acceptance. The pipeline does
not treat a committed receipt as normalized evidence or a detected incident.
No unsupported event is quarantined or automatically converted to another schema.
A rejected or unacknowledged sender record remains recoverable according to M5.5.

## Verification

`knetsentry_event_ingestion_contract` runs in all seven presets using the existing
synthetic enrollment/TLS executable. It exercises unauthorized and unenrolled
identity, invalid configuration, wrong binding/source, malformed and oversized
rows, all three supported profiles, four admitted idle receivers, overload,
deadline recovery, abandoned receiver cleanup, exact retry, conflicting cursor,
sink refusal, revocation while admitted and aggregate disposition counts.
Existing M5.5/M5.8 regressions remain mandatory and now traverse the pipeline,
including lost ACK and sender/receiver commit faults.

Accepted M6.1 inventories: desktop 61/55, core-only 48/49 (normal/sanitized), 396
CTest executions across seven lanes. Maintainer qualification recorded 117 PASS,
0 FAIL, 0 SKIPPED, 0 BLOCKED; 30 repeated Release and 15 repeated sanitized
executions, direct ingestion and delivery, agent lifecycle and reported manual
GUI verification passed. Nine hosted checks passed on `f70966f` and merge was
reported. See [M6.2](EVENT_NORMALIZATION_M62.md) for the subsequent typed
normalization integration; the original receipt and ACK contract is unchanged.
This adds partial TB-04/TB-06/TB-07 and TV-06/TV-07/TV-13/TV-25/TV-26 evidence;
no threat is closed. Full operational C-11 integration, generic envelopes,
normalization, storage retention, independently authorized privacy policy,
network admission and global resource budgets remain future requirements.

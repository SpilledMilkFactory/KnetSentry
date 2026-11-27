<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M7.4 — Privilege and system-integrity detections

Issue #63, stored Audit-record detection foundation. The immutable catalog in
KnetSentry::Detection uses exact native numeric record types, not new OCSF
classes, outcomes or a user-supplied rule language. The caller explicitly
selects an authorized EventStore, full configured endpoint binding, trust and
coverage. All rules have version 1 and return store-scoped evidence IDs, fixed
rule IDs, rule severity, numeric record type and caller coverage. A finding
is a candidate for future alert administration, not a persistent alert.

## Catalog

| Types | Observation | Priority |
| --- | --- | --- |
| 1130, 1131 | Service start/stop records | Informational |
| 1203, 1305 | Audit daemon/system configuration activity | Medium |
| 1321, 1322 | File capability and capset activity | Medium |
| 1325, 1330 | Netfilter configuration and kernel module activity | Medium |
| 1403, 1404 | Mandatory access-control policy load/status activity | Medium |
| 1702, 1703 | Kernel-reported suspicious file-link/file-creation activity | High |
| 1800, 1801, 1802, 1804, 1805, 1807 | Integrity verification, status, PCR invalidation and policy records | Medium |

Numeric type meanings follow the Linux UAPI audit.h and userspace Audit ABI
(SERVICE_START/STOP 1130/1131; see upstream audit-userspace record definitions).
Only the listed exact types match; unknown numbers are counted as unmatched,
not declared safe. Type alone cannot prove successful escalation, actual
configuration modification, service identity, malicious intent, or a failed
integrity verification. No outcome is invented. Rule severity is a review
priority, not original event severity. Record-level findings are not assembled
multipart Audit events; shared audit IDs do not establish duplicate records.

## Storage and security

The internal EventSummary projection now carries the existing policy-approved
numeric Audit type from the validated normalized record. Non-Audit summaries
carry zero. Existing GUI IPC does not serialize the new field (decoded GUI
summaries have zero); neither the OCSF mapping nor database schema changes.
Memory, SQLite and split stores use the existing summary projection path.
No native cursor, audit ID, raw message, command, account, path or payload is
read by the detector or copied into findings. The existing trusted store
contract must enforce the exact endpoint binding selector. The detector does
not independently authenticate the endpoint or authorize store access.

At most four ascending pages of 32 records, 128 observations and 128 findings.
Invalid scope or evidence, missing/out-of-range type, non-increasing IDs,
malformed pages, backend failure, stale revision and any pending index entry
refuse the whole report. Unverified trust is refused before search. Allocation
failure propagates. No writes, new privileges, network, clock dependency,
manager activation, GUI or AI dependency. A successful empty scan is not proof
of safety or complete coverage. Store identity must be retained by the caller.

## Remaining issue scope

M5.6 FIM reports local changes but has no persisted FIM event envelope. This
increment does not infer file tampering from generic Audit integrity types or
invent stored FIM records. Persistent FIM evidence integration, confirmed
integrity-failure semantics where supported by an explicitly approved source,
and durable alert lifecycle remain outstanding. Keep #63 open for remaining
acceptance scope; this increment does not claim full issue closure.

## Qualification

The mandatory `knetsentry_system_integrity_contract` covers synthetic canonical
Audit admission, normalization, every catalog rule, unknown types, exact scope,
trust, evidence linkage, deterministic output, capacity, malformed pages and
pending-index refusal. Existing SQLite and split-store tests now also check
Audit summary projection after restart. Target Ubuntu qualification pending.

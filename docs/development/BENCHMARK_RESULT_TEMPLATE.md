<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Benchmark Evidence Template

**Issue:** M0.5. Copy this template **only after a real test run**. Empty
fields or example text do not constitute measured results.

## Run identity

| Field | Value |
| --- | --- |
| Run ID / timestamp and timezone | `NOT_RUN` |
| Status (`PASS`/`FAIL`/`INCOMPLETE`/`INVALID_RUN`/`NOT_RUN`) | `NOT_RUN` |
| Workload / benchmark IDs | `NOT_RUN` |
| Git commit and executable SHA-256 | `NOT_RUN` |
| Fixture SHA-256 / seed / expected counts | `NOT_RUN` |
| Ubuntu/kernel/GCC/Qt/KDE/CMake versions | `NOT_RUN` |
| CPU/RAM/disk/NIC / cgroup / power / VM or bare metal | `NOT_RUN` |
| Effective config and monitoring scope hash | `NOT_RUN` |
| Source mix, capture snaplen, buffering, SQLite mode | `NOT_RUN` |
| Raw volume identity/path/filesystem and index volume identity/path/filesystem | `NOT_RUN` |
| Mount substitution, spool policy, per-volume reserve and encryption status | `NOT_RUN` |
| Clock skew estimate and time-source status | `NOT_RUN` |

## Results (populate for each independent iteration)

| Metric | Target / definition | Observed | Evidence path |
| --- | --- | --- | --- |
| Accepted events/s and submitted/received/rejected/duplicate/durable counts | Per W-01/W-02 | `NOT_RUN` | `NOT_RUN` |
| Delivered packets/s and kernel/broker/parser loss | Per W-03/W-04 | `NOT_RUN` | `NOT_RUN` |
| Durable and alert latency p50/p95/p99/max | KS-PERF-009/010 | `NOT_RUN` | `NOT_RUN` |
| Search p95, GUI interaction p95, UI frame p95 | KS-PERF-011/012/013 | `NOT_RUN` | `NOT_RUN` |
| Per-process RSS/PSS, CPU, I/O, PSI, queue peaks | KS-PERF-016..021 | `NOT_RUN` | `NOT_RUN` |
| Store bytes/event, amplification, storage reserve | KS-PERF-033..036 | `NOT_RUN` | `NOT_RUN` |
| Restart/restore time, RPO, source degradation time | KS-PERF-028..032,038 | `NOT_RUN` | `NOT_RUN` |
| Applied security controls and scope verification | KS-PERF-040 | `NOT_RUN` | `NOT_RUN` |
| Raw-first durable segment count, index lag, mount validation and no fallback | KS-PERF-041..054 | `NOT_RUN` | `NOT_RUN` |

## Required notes

Document lost/unacknowledged data separately, known blind spots, source
attribution and trust, dataset limitations, controls still unimplemented,
time-outs, instrumentation gaps, changes since the preceding baseline,
and all deviations. Attach per-iteration JSON/CSV counters, logs, fixtures,
hashes and executed commands. Do not use real sensitive telemetry in a public
repository without authorization and redaction.

## Acceptance

`NOT_RUN` — This file is a template, not evidence. Required tests and
performance controls are scheduled for future issues and M14 qualification.

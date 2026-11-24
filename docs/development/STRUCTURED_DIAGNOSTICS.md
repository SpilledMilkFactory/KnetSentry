<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M1.6 — Structured diagnostics and sensitive-data boundary

**Status:** Initial C++23, Qt-independent diagnostic publisher only. This is
**not** an evidentiary audit log, a security-event feed, a persistent raw log,
or an authorization control. Follow-up ownership: M2.5 for durable, ordered
security audit transport and failure policy (see [M2.5 audit contract](SERVICE_AUDIT_M25.md));
M6 for evidence/index storage.

## Contract and traceability

Implements an initial portion of architecture interface `I-21`, threat `TH-033`
and prospective test `TV-25`. M0 threat residual risk remains unverified until
complete multi-process audit, retention, privacy and CI/artifact review gates.
The desktop must remain unprivileged; no monitoring, public Internet access,
or raw-event storage is added by M1.6.

## Event schema

One newline-terminated JSON object per diagnostic record, maximum **512 bytes**
including newline. `schema=1`, `time_unix_ms` (UTC Unix epoch milliseconds),
`sequence` (monotone per logger instance, **not** durable audit ordering),
`level`, `component`, `event`, `outcome`, `count` (unsigned integer or null),
and `private_detail` (null or literal `[REDACTED]`).

All event, component, outcome and severity values are fixed C++ enum mappings:
no variable string is serialized. `SensitiveContext` is not dereferenced by
the logger; presence alone produces `[REDACTED]`, even for multiline secrets,
header values, paths, endpoints, credentials or malicious JSON fragments.
This is **deny-by-construction**, not a claim that arbitrary untrusted strings
can be made safe using regex-based scrubbing. Never replace enum codes with
user-controlled message text. Counts are explicitly approved non-sensitive
aggregates only; callers must evaluate whether a count itself is private.

Unknown/invalid enum values are rejected rather than logged.

One `DiagnosticLogger` protects its stream/sequence with a mutex. Each write
formats in a fixed-size stack buffer, validates bounds and sink status, flushes,
and reports failure to the caller as `false` without reflecting exception text.
It is synchronous and may block on a slow sink. Caller must not use it for
high-throughput telemetry, privileged audit enforcement, or latency-sensitive
Qt render callbacks. Do not confuse an emitted line with durable evidence;
stream truncation and interruption can lose records. File permissions, queue
bounds, secure rotation, integrity, retention, and sink authentication are not
part of M1.6.

The desktop now emits only fixed, low-cardinality lifecycle records to
`std::clog` (stderr), including start, QML ready and QML root rejection. This
provides no new file/network output. `--version` and `--help` remain clean,
headless commands. Failures to write non-authoritative diagnostics must not be
misrepresented as audit success; a fixed, non-sensitive fallback message may
appear. This component does not intercept or sanitize Qt/Kirigami's **own**
raw framework diagnostic messages, which may contain environment-specific
paths. Review terminal logs before publishing. Do not copy raw framework logs
into security evidence or public CI artifacts without independent redaction.

## Verification

```bash
python3 scripts/verify_m16_diagnostics.py
cmake --preset linux-core-only --fresh
cmake --build --preset linux-core-only --parallel
ctest --preset linux-core-only --output-on-failure
python3 scripts/verify_m16_diagnostics.py --build-dir build/presets/linux-core-only
```

The `knetsentry_structured_diagnostics` CTest calls the C++ probe through the
Python JSON validator. It emits 131 records, including a sensitive multiline
secret, an unsigned 64-bit maximum count, and 128 concurrent records. Tests
assert schema/sequence/bounds, no secret markers in stdout, and no dynamic
string field. A broken sink and an invalid event enum are tested explicitly. Intentionally malformed
synthetic logs are rejected by the validator. Sanitizer configurations must
also run the test. A source-only PASS is **not** runtime qualification.

In non-sanitized desktop configurations, `knetsentry_desktop_diagnostic_lifecycle`
runs the real QML smoke mode and checks that the application emits exactly
`gui_starting` and `gui_ready` records. Framework warnings are not considered
part of our structured-record stream. The existing sanitized QML smoke test
covers instrumented startup without expanding the LSan suppression policy.

On the Ubuntu 26.04 supported desktop run Release, Debug, ASan/UBSan and Clazy
configure/build/CTest; ensure Qt/Kirigami startup and the earlier 7-page
navigation still pass. Confirm the GUI still reports monitoring unavailable.
Do not publish unsanitized stdout/stderr from other components.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M2.4 — Service health and diagnostics (#21)

The Qt-independent manager provides a bounded, on-demand health snapshot
through the existing opt-in `I-01`/`TB-05` Unix-domain IPC channel. This
extends the `C-01` manager health coordination and is an initial subset of
`C-19`/`I-21` health reporting, not a durable audit service. It preserves
`KS-NET-012` local authorization and the `TH-010`/`TH-038` mitigation scope;
no full threat or verification-gate closure is claimed.

## Authorization and compatibility

Only the matching effective UID/GID principal verified via `SO_PEERCRED`
can issue `HEALTH`. The per-operation allowlist remains default-deny, including
all administrative operations. `STATUS` retains its exact M2.3 response and
64-byte response limit; requests for either operation remain at most 64
bytes. `HEALTH` has a separate maximum response of 256 bytes. No listening
socket is created unless `--ipc-dir` is explicitly supplied. No Qt, new
third-party dependency, network listener, privileges, egress, storage, or
monitoring is enabled. Existing socket and configuration gates remain intact.

## Wire contract

The existing four-byte unsigned big-endian length prefixes both request and
response. One request per connection, strict ASCII, 16 lowercase hex ID, and
one terminating LF. The ID is a correlation value, not an authentication
credential. For example (illustrative numbers only):

```text
KSIPC/1 HEALTH 0123456789abcdef\n
KSIPC/1 OK 0123456789abcdef HEALTH RUNNING 1234 2 4096 CONFIG_DEFAULT IPC_READY MONITORING_UNAVAILABLE 0 0 0\n
```

The positional fields following `HEALTH` are:

| Field | Meaning |
| --- | --- |
| `RUNNING` | Existing lifecycle must be Running; other states cannot serve a health response. |
| `uptime_ms` | Monotonic milliseconds since manager health tracker creation during non-root startup, not wall time or system uptime. Linux steady clock excludes suspended time. |
| `cpu_ms` | Cumulative user plus system CPU time of this process (not percent or host CPU); truncated to milliseconds. |
| `peak_rss_kib` | Linux `getrusage(RUSAGE_SELF)` peak resident set size in KiB, not current RSS, virtual memory, or system memory. |
| `CONFIG_DEFAULT` / `CONFIG_VALIDATED` | Built-in safe defaults or successfully validated explicit startup configuration, not a configuration dump or continuous revalidation. |
| `IPC_READY` | This process is serving through the validated local socket. |
| `MONITORING_UNAVAILABLE` | Operational monitoring is not implemented; no claim of LAN visibility. |
| `rejected` | Connections rejected for credentials, invalid lengths, malformed/unknown requests or unauthorized operations. |
| `transport_errors` | Accepted-client header/payload read failure, including timeout/EOF, or response write failure. |
| `sampling_errors` | Health samples missing either resource value, or health encoding failures. |

Unsigned integers are decimal uint64 values; only resource fields may be
`NA` if sampling fails or the value is invalid. CPU arithmetic is checked;
zero CPU is valid. A nonpositive peak RSS is unavailable. Sampling errors
are included in the current response when possible; response write errors
are visible to subsequent requests. All counters saturate at uint64 max,
reset on process restart, and count neither unique peers nor incidents.
A request cannot alter configuration or reset counters. Invalid input returns
no data. Fixed-size encoding rejects invalid state, IDs and insufficient
space; no partial payload is intentionally emitted by the encoder. The
client must reject a truncated transport frame. No user-controlled paths,
peer identifiers, raw error strings or telemetry are included.

The manager remains single-threaded and performs only one resource syscall
per authorized health query. No background sampler, unbounded history,
queue or request-generated log stream is introduced. Existing serial IPC
backlog and per-stage 250 ms wait bounds remain; same-user denial of service
is not eliminated. A daemon that fails before readiness or later terminates
cannot answer health; existing fixed lifecycle diagnostics and exit codes
remain authoritative for those failures. Health is not a watchdog, complete
component availability proof, or a persistent audit trail. No GUI polling
or service deployment is part of this issue.

## Verification

```bash
python3 scripts/verify_m24_health.py
python3 scripts/verify_m24_health.py --build-dir build/presets/linux-release
```

The compiled contract checks checked CPU arithmetic, saturating counts,
maximum-width encoding, unavailable fields, invalid states/IDs, insufficient
capacity and live process sampling. The runtime test starts actual managers
with both configuration modes, validates response framing, uptime progression,
resource monotonicity, compatibility, negative requests, timeouts, exact error
counts and shutdown cleanup. Cross-UID live tests run when the harness can
switch identity (root parent, non-root manager); ordinary non-root runs report
NOT_APPLICABLE for this subcase. The existing compiled UID/GID matrix covers
identity mismatches without needing privilege. All tests use synthetic inputs.
A kernel resource-syscall failure is not induced in the live test; unavailable
encoding and error accounting are exercised in the compiled test.

Expected CTest counts: 21 desktop Release/Debug/Clazy/analysis; 18 full
sanitizer; 13 core-only Release; 14 core-only sanitizer. The seven presets
and nine CI jobs remain unchanged. These are acceptance targets, not a
claim of hosted or Ubuntu desktop execution.

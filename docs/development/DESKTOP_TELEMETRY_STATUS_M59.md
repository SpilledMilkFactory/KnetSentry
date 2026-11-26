<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M5.9 — Local endpoint telemetry status in the desktop

## Scope and authorization

The independent endpoint agent can optionally publish a bounded local aggregate
status stream. The desktop exposes its current report on Dashboard and Assets
through six read-only Qt properties, separately from manager health and the
manager-selected enrollment registry. An approved registry entry is not a live
agent or a collection measurement. No manager receiver, remote endpoint session,
new network authority, agent administration or security-event ingestion is
introduced. Issue #46 remains outstanding; multi-endpoint authenticated status
integration remains future work under #50. This is a local presentation foundation.

The ordinary-user launcher explicitly supplies a single-writer pipe/FIFO (write
fd 3 for the agent and read stdin for the desktop). Neither process discovers a
status path, connects a socket, starts the other process, or reads private
telemetry stores on behalf of the viewer. The agent requires the prefix
`--status-stream` before `--run`, in addition to the unchanged mandatory active
collector privacy policy; the desktop requires `--agent-status-stdin`. Both
reject inappropriate descriptor types/directions; root desktop attachment is
rejected. Agent validation and privilege normalization precede attachment and
collector construction. No new dependencies or privileges are required.

This explicit opt-in permits aggregate counts and timing information to be shown
locally. They can themselves be sensitive. The launcher must select an authorized
single writer and reader, avoid public or shared FIFOs, and not publish the stream
as evidence of authenticated enrollment. The descriptor is a launcher-controlled
capability, not independent cryptographic identity or authorization. Same-UID or
privileged writers, relays and substituted launchers can fabricate reports.

## Status schema and semantics

`KSSTAT1` is a newline-terminated ASCII record with seven tab-separated fields:
version, collector, health, host-monotonic timestamp (ms), interval observation
count, interval duration (ms), and optional queued record count (`-` unavailable).
The fixed collector names are `none`, `journal`, `authentication`, `audit`, `fim`,
`fim-metadata`. Health is `idle`, `active`, `paused`, `blocked`, `source-failed`, or `failed`.
The stream does not contain file paths, units, message contents, event categories,
cursors, policy strings, fingerprints, IDs, credentials or error details.

- `idle`: lifecycle-only agent, no collector or measured rate.
- `active`: one local collector successfully polled; monitoring coverage unknown.
- `paused`: buffered journal-family collector has reached 128 queued records.
- `blocked`: buffered source failure; a retained queue may remain accessible.
- `source-failed`: unbuffered journal-family source failure; the agent terminates.
- `failed`: other startup or polling failure (including unsafe FIM observation); the agent may terminate. Rate and queue
  are unavailable. The last reported failure may remain labeled historical after
  stream expiry or closure, not as current source state.

For successful journal-family polls the interval count is the number of newly
committed rows, excluding previously persisted rows. FIM counts fixed change
observations, not security incidents. The first report has no rate; subsequent
successful reports express count / elapsed monotonic interval (up to 60 s).
Zero is only shown with an actual measured interval. Failed, source-failed, blocked, paused and
idle reports do not yield a rate. Queue occupancy is not delivery throughput.
Full and metadata-only FIM are distinguished, and no FIM queue is implied.

The producer emits at completed polls (normally approximately one second apart)
without a second collection thread. A bounded atomic nonblocking write drops
reports on pipe pressure; EPIPE disables reporting rather than stopping the
agent. The reported interval follows attempted sampling, not receipt cadence.
Status does not extend collection permissions, modify collector persistence, or
establish delivery acknowledgement. Diagnostic stdout/stderr retains the
existing interface; do not pipe those diagnostics into the status reader.

The reader accepts only a pipe read descriptor and validates bounded complete
lines (160 bytes maximum, 4096 bytes read per 250-ms Qt tick), fixed enums,
canonical integers, fixed per-stream collector mode, mode/state consistency and monotonic timestamps. Reports
older than five seconds do not establish current state; the model expires stale
measurements, clears them on EOF or malformed/replayed reports, and does not
automatically attach to a different stream. Polling may resume on a fresh valid
report following staleness. The model does not provide source-failure histories,
cryptographic identities, per-endpoint correlation or fleet-wide rates. Rates
are sampled local observations and not lossless event counts or incident rates.

## Manual demonstration (synthetic only)

From the repository root, ordinary user, build the Release preset. Use a private
temporary directory and FIFO to observe an explicitly authorized synthetic file:

```bash
umask 0077
fixture=$(mktemp -d /tmp/ks-status-m59.XXXXXX)
mkfifo "$fixture/status"
printf 'synthetic\n' > "$fixture/watched"
policy="v1;collector=fim;allow-path=$fixture/watched;redact=fim-content;redact=fim-slot"
./build/presets/linux-release/apps/agent/knetsentry-agent \
    --status-stream --run --schema-version 1 --collectors fim \
    --path "$fixture/watched" --privacy-policy "$policy" 3>"$fixture/status" &
agent_pid=$!
./build/presets/linux-release/apps/desktop/knetsentry \
    --agent-status-stdin <"$fixture/status" &
desktop_pid=$!
```

Open Dashboard or Assets. Expect metadata-only FIM, local polling, an initially
unavailable rate followed by measured zero, unavailable queue and remote
monitoring still unavailable. `chmod 400 "$fixture/watched"` should yield one
local change observation in a subsequent interval. The rate may return to zero
on the following report. No private file is read for content. Pause the agent
with `kill -STOP "$agent_pid"`; after five seconds plus the reader tick the rate
and collector should become unavailable. Resume with `kill -CONT "$agent_pid"`.
To demonstrate terminal unsafe-source failure, create a synthetic symlink at a
separate fixture path, then atomically replace `watched` with it. Expect the
agent to exit 1 and current measurements to clear, with a historical failure
notice if the final report was received. Alternatively stop the agent with
SIGTERM and verify normal disconnection. Terminate only these fixture PIDs; if
startup fails, close the desktop and terminate the fixture agent. Remove the
FIFO and synthetic directory after both processes have exited. No private
collector stores are needed for this demonstration.

## Verification and remaining scope

`knetsentry_telemetry_status_contract` covers strict parsing, partial reads,
expiry/recovery, malformed/replayed records, EOF and saturated pipe pressure. `knetsentry_telemetry_status_runtime`
exercises the actual ordinary-user agent with synthetic metadata-only FIM,
measured change, failure, observer closure and non-pipe rejection. Both run in
all seven presets. Existing Qt health model and navigation tests include status
properties and unconfigured/active/blocked/disconnected behavior. The separate
non-sanitized `knetsentry_gui_telemetry_runtime` exercises actual rendered
Dashboard/Assets bindings with a synthetic report pipe; the Qt model remains
covered under sanitizers without new third-party QML leak suppressions.

The target inventories are desktop 60/54 and core-only 47/48 (normal/sanitized),
389 CTest executions across seven lanes. Target-host and hosted qualification
remain pending. This contributes partial TB-06/TB-07 and TV-13/TV-25 evidence
for minimized status publication and bounded untrusted report handling; it does
not close a threat or qualify operational I-07, independent authentication,
remote endpoint status, receiver-side privacy, secure policy administration or
release readiness. No production manager changes are made.

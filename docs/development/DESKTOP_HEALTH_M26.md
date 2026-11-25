<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M2.6 — Desktop management daemon health

Issue #23. The desktop (`C-03`, `C-20`, `P-02`) projects a narrow read-only
health snapshot through the existing `I-01` / `TB-05` boundary; this is an
initial state update for `I-23`, not the future paginated security-data model.
`KS-NET-012`, `TH-010`, `TH-011` and `TH-038` remain relevant. No threat is
claimed closed. The manager remains the authority; QML does not open sockets,
read databases, change policy or request privileged actions.

## Usage and current state

In terminal one, as an ordinary user:

```bash
IPC_DIR=$(mktemp -d "$HOME/.ks-ipc.XXXXXX")
printf '%s\n' "$IPC_DIR"
./build/presets/linux-release/apps/manager/knetsentryd --ipc-dir "$IPC_DIR"
```

In terminal two, use the exact printed directory:

```bash
./build/presets/linux-release/apps/desktop/knetsentry --ipc-dir ABS_DIR
```

With no `--ipc-dir`, the desktop starts normally and makes no requests. A
configured desktop performs its first query on startup, then every 30 seconds.
One query is in flight at most, with a two-second monotonic exchange deadline
and fixed buffers. During each refresh the old snapshot is cleared, and it is
never displayed after a failed query. Status represents a last verified sample,
not a persistent connection or proof the manager is still alive. Stop the daemon
with Ctrl+C; within the next refresh and timeout the dashboard should show
unavailable and no previous measurements. Restart the daemon with the same
IPC directory; within the next refresh a new snapshot should appear. Do not
run as root. Root desktop IPC is disabled. Closing the GUI closes the client;
no daemon start/stop authority is acquired. Remove the empty IPC directory
only after stopping the daemon and closing the GUI.

The dashboard shows daemon lifecycle, configuration mode, local IPC state,
monotonic uptime (ms), cumulative CPU time (ms), peak RSS (KiB), and the three
operational error counts, preserving all 64-bit decimal values as text instead
of converting them to JavaScript numbers. `NA` resources are shown unavailable.
No monitoring coverage, incident data or audit-integrity claim is inferred.
All seven routes and the monitoring-inactive notice remain present.

## Client boundary

The Qt-independent client uses one Linux AF_UNIX stream with SOCK_NONBLOCK and
SOCK_CLOEXEC. It verifies the final directory is service-user-owned mode 0700
and the socket is owned by the same user and mode 0600, rejects relative paths,
dot segments and final symlinks, and checks kernel SO_PEERCRED UID/GID and positive
PID on the connected descriptor before transmitting a request. It accepts only
one correlated KSIPC/1 HEALTH response, with a 1..256 byte payload and EOF;
trailing bytes, truncation, unexpected tokens, noncanonical numbers, overflow,
invalid states and unsupported versions are rejected. No raw response strings,
paths, correlation identifiers or peer identities are projected into QML or
logged. There are no new Qt dependencies in the manager or core-only targets.
The event loop advances nonblocking socket operations at 25 ms only while an
exchange is pending. Filesystem pathname lookup itself is synchronous and not
hard latency bounded; use a local IPC directory, not slow remote storage.

This initial identity policy does not authenticate a particular executable or
isolate processes sharing the same Unix UID/GID. Path metadata checks are defense
in depth, not protection from a hostile same-user process or ancestor-path races.
No root or remote management is introduced. The GUI has no audit-file access.

## Audit interaction

When the M2.5 audit sink is enabled, each HEALTH authorization consumes an audit
record. One configured GUI makes approximately 120 queries per hour, plus its
initial query. The 1 MiB session budget remains finite; actual lifetime depends
on record sizes and other traffic. Do not leave an audited development session
running indefinitely. Closing the desktop stops its polling. Audit exhaustion
still fails closed, and the GUI will display unavailable after the next failed
refresh. No audit bypass, rotation, or increased budget is introduced. The
shorter cadence used by `--self-test-health` is a bounded synthetic test-only
mode, not normal polling. The GUI does not know whether auditing is enabled.

## Qualification

Run the dedicated structural verifier and the configured CTest inventory.
Native parser and live tests cover real manager availability, fragmented frames,
truncation, oversized frames, invalid correlation, stalled peer, unsafe path,
and conditional cross-UID server rejection before request disclosure. The Qt
model test covers unconfigured and unavailable state; the actual offscreen QML
runtime test starts, stops and restarts a real manager and checks all four
presentation bindings plus clearing of resource/counter values. The latter
runs only in non-sanitized desktop presets under the established QML LSan
policy; no additional suppression is added. Existing sanitized QML startup and
navigation plus the sanitized Qt model and native client tests remain required.
Expected CTest totals: desktop 27/23 (normal/sanitized); core-only 17/18
(normal/sanitized). The full Ubuntu desktop matrix and manual visual checks
remain required before acceptance.

M2.7 introduces a separate dedicated system-service identity; its private socket
is intentionally inaccessible to ordinary desktop users under the existing
matching UID/GID policy. See [systemd deployment](SYSTEMD_SERVICE_M27.md).
The same-user foreground GUI workflow remains unchanged.

### M2.9 desktop toolbar

See [M2.9 toolbar contract](DESKTOP_DAEMON_TOOLBAR_M29.md). The existing explicit
IPC endpoint remains read-only; desktop-owned foreground lifecycle is separate.
The new desktop CTests are `knetsentry_qt_daemon_control` (including sanitizer)
and `knetsentry_gui_daemon_toolbar` (non-sanitized). Core-only counts are unchanged.

M3.8 extends this same health model and real GUI runtime regression for
read-only Settings scope inspection; see [desktop scope contract](DESKTOP_NETWORK_SCOPE_M38.md).
The test now includes a fixed rejected IPC operation and a restart with a
validated v1 configuration. The wire format and ordinary refresh cadence
are unchanged.

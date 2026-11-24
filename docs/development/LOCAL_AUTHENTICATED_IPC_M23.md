<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M2.3 — Local authenticated IPC contract (`I-01`, `TB-05`)

**Issue:** #20 · **Target:** Ubuntu 26.04 AMD64 · **Status:** limited, read-only IPC implemented; full authorization/admin control plane NOT implemented.

## Security model and scope

`knetsentryd` optionally exposes a **pathname `AF_UNIX` SOCK_STREAM** listener
inside an already existing, private directory owned by its effective user.
No TCP, UDP, AF_INET, abstract socket, remote control listener, Qt, DB,
network monitoring, packet capture, privileged response, or public egress is
introduced. This is *local IPC*, not a `network_listeners_enabled` capability.
Without `--ipc-dir`, M2.2 lifecycle-only behavior remains unchanged.

The caller supplies a private, already created directory (mode **0700**).
The daemon requires a canonical-form absolute path without empty, `.` or `..`
components, validates the final directory with `O_DIRECTORY|O_NOFOLLOW`,
checks effective UID ownership and mode 0700, rejects any pre-existing
`manager.sock` entry (including stale sockets and symlinks), and binds with
umask 0177. The socket is created immediately with mode **0600**. A bind or directory verification
failure stops startup without `manager_ready` and without trying a fallback
path. Only the socket inode created by this process is unlinked on normal
exit; no pre-existing files are ever removed. A crash can leave a stale
socket, which requires the operator to verify and remove it manually.

Linux `SO_PEERCRED` is queried for every accepted connection. The kernel
reports a PID, UID, and GID at connection time; the daemon requires a positive
PID and both UID and GID to match the current service process. Authentication
of the local process identity does *not* imply that submitted payloads are
trustworthy. A **default-deny** operation matrix grants this identity only
read-only `STATUS`; no administrative operation exists in M2.3. Other UIDs,
GIDs, unknown roles, unsupported versions and all other actions are rejected.
There are no client-supplied UID/role claims or secret tokens.

**This is intentionally not a multiuser administrative policy.** Same UID/GID
is a restricted initial Viewer principal for a deliberately non-sensitive
response. Any other process running with the same user identity can issue that
same read-only request. A real dedicated service identity, operator-group
roles, ACLs, protected management operations, case access and policy
modification require separate design, audited authorization and negative
qualification in later M2 issues (especially **M2.4** and **M2.8**). Do not
interpret this milestone as complete operator authentication or access control.

## Framing / message contract

Wire encoding v1 has a four-byte **big-endian unsigned payload length**, then
strict ASCII. Maximum request and response payload: **64 bytes**. Empty,
overlong, partial, unsupported or malformed frames close the connection.
One request per connection; no sessions, streaming or pipelining.

Accepted request (16 lowercase hex request-id characters):

```text
KSIPC/1 STATUS 0123456789abcdef\n
```

Response payload:

```text
KSIPC/1 OK 0123456789abcdef LIFECYCLE_ONLY\n
```

The request ID is only a correlation token, **not** an authentication secret,
anti-replay token or audit identifier. The response does not disclose service
configuration, user data, security telemetry or monitoring health.
`LIFECYCLE_ONLY` explicitly means the operational SIEM is not available.
All other operations are denied; no setting, state or policy is mutated.

A serial, nonblocking listener caps pending connection backlog to eight and
individual read/write waits to 250 ms per direction. Peer credentials are
verified *before* parsing message content. The manager prioritizes shutdown
signals via Linux `signalfd` and `poll`; no asynchronous C++ signal handler is
added. Single-threaded request handling remains susceptible to local
same-user resource exhaustion: this is a bounded foundation, not a fully
DoS-resistant broker, rate limiter or resource quota implementation. Those
limits must be enforced and tested in subsequent manager/sandbox issues.

No private request content is logged. All diagnostics retain M1.6 fixed event
identifiers; they remain **non-authoritative**, not signed audit evidence.

## Example manual acceptance

```bash
# Operator, not root. Use a short, private path on a private filesystem.
mkdir -m 700 "$HOME/.knetsentry-ipc"
./build/presets/linux-release/apps/manager/knetsentryd --ipc-dir "$HOME/.knetsentry-ipc"
# In a second terminal, query the same-UID listener:
python3 - <<'PY'
import socket, struct
from pathlib import Path
path = Path.home() / '.knetsentry-ipc/manager.sock'
request = b'KSIPC/1 STATUS 0123456789abcdef\n'
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(2)
    client.connect(str(path))
    client.sendall(struct.pack('!I', len(request)) + request)
    header = client.recv(4)
    if len(header) != 4:
        raise RuntimeError('no reply header')
    size = struct.unpack('!I', header)[0]
    assert size <= 64
    data = bytearray()
    while len(data) < size:
        piece = client.recv(size - len(data))
        if not piece:
            raise RuntimeError('incomplete reply')
        data.extend(piece)
    print(bytes(data).decode('ascii'), end='')
PY
# Press Ctrl+C in the daemon terminal. The process-owned manager.sock is removed.
```

Optional combined invocation: `knetsentryd --config ABS_PATH --ipc-dir ABS_DIR`.
The schema-v1 configuration's `network_listeners_enabled = false` remains
mandatory because Unix-local IPC is not an Internet or LAN listener. Invalid
explicit configuration still fails **before** any socket is opened.

Run negative tests and compiler gates:

```bash
python3 scripts/verify_m23_ipc.py
python3 scripts/verify_m23_ipc.py --build-dir build/presets/linux-release
ctest --preset linux-release --output-on-failure
ctest --preset linux-sanitize --output-on-failure
reuse lint
```

The tests reject unauthorized operations, bad protocol versions, invalid IDs,
unsafe directories, pre-existing socket entries, overlong and slow inputs,
and incorrect response schemas. When run by root in a disposable test
namespace, the harness starts the daemon as `nobody` and also verifies real
cross-UID rejection (root intruder). On ordinary nonroot CI runners that
cannot switch identities, cross-UID kernel behavior remains **not independently
exercised**; compiled authorization unit tests cover mismatched UIDs/GIDs.
Tests never create TCP sockets or privileged monitoring operations.

## Residual risks and exclusions

- **Same-user trust:** identity equality alone does not differentiate two
  processes of the same UID. No privileged or sensitive operation is exposed.
- **Parent-directory/path races:** the final directory is checked with
  `O_NOFOLLOW`; a hostile owner of a mutable parent path, or another process
  with the same UID, could replace path components. Complete anchored
  `openat2` path resolution and service-managed runtime directory are future
  hardening requirements. Do not deploy in attacker-controlled parents.
- **Socket-file races:** cleanup uses original device/inode checks; same-UID
  manipulation during bind, chmod or cleanup is not fully prevented.
- **Availability:** a malicious authorized local process can exhaust the
  bounded serial listener. No per-user quotas or durable audit trail exists.
- **Service identity:** systemd unit, sandbox, dedicated user and deployment
  controls are not yet provided or qualified.
- **Version negotiation:** unsupported protocol versions fail closed. No v2
  or automatic migration path has been defined.
- **Not SIEM-ready:** no endpoint collection, monitoring, storage, response,
  AI or threat intelligence is activated by this change.

A secure local transport is a prerequisite, not itself proof of a complete
protected control plane. Future changes to operations require explicit
per-action authorization and new negative tests before any privilege is added.

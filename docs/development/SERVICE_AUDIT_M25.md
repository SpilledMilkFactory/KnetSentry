<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M2.5 — Structured service audit logging

Initial persistent audit subset for `C-19` and `I-21`, covering `TB-05` and
`TB-07`. Preserves the peer authorization boundary (`KS-NET-012`, `TH-010`)
and advances the logging privacy mitigations of `TH-033` / `TV-25`. No threat
closure, tamper-proof storage, or independent audit qualification is claimed.

## Activation and lifecycle

The existing foreground lifecycle and IPC modes remain compatible. Durable
service auditing is explicitly opt-in using `--audit-dir ABS_DIR`; omitting
that option produces only the existing non-authoritative diagnostics. No
administrative mutations are enabled in either mode. Use audited mode for
security-relevant testing; future privileged operations must require an
approved audit sink rather than use the compatibility mode.

```bash
umask 077
mkdir -m 700 "$HOME/.knetsentry-audit"
mkdir -m 700 "$HOME/.knetsentry-ipc"
./build/presets/linux-release/apps/manager/knetsentryd \
    --audit-dir "$HOME/.knetsentry-audit" --ipc-dir "$HOME/.knetsentry-ipc"
```

Run options `--config`, `--ipc-dir`, `--audit-dir` may appear once each in
any order. `--help`, `--version`, and standalone `--check-config` remain
non-service commands; command-line rejection and root refusal before opening
an audit sink are reported outside the audit file. Startup configuration
selection/validation/rejection is audited; no live configuration changes exist.

The directory must already exist, be owned by the effective service UID,
and have exactly mode 0700. All path components are opened relative to
pinned directory descriptors with no symlinks, empty/dot/dot-dot segments,
or overlong components. Use a trusted local filesystem and ancestors. The
file `service-audit.jsonl` is created exclusively with mode 0600, append-only
open semantics, no symlink following and close-on-exec. Existing entries of
any kind are rejected without changes. No automatic deletion, overwrite,
reopen or rotation occurs. The directory is synced at creation. For a new
session, select a fresh private directory and preserve old files privately.

## Record format and attribution

Schema 1 JSONL, each record at most 512 bytes including newline. Fields:
`schema`, `session` (128-bit kernel random lowercase hex), `sequence`
(starting at 1), `time_unix_ms` (wall clock), `service_pid`, `service_uid`,
`service_gid`, `event`, `outcome`, and `peer` (kernel PID/UID/GID object or
null). Sequence establishes order within one session even if wall time
changes. PID can be reused; credentials identify a Unix process identity,
not a named human, administrator role or signed identity. A peer identity
is only attached when SO_PEERCRED returned a valid record; null never
pretends to identify a caller. The serial IPC path orders authorization
and any subsequent transport or sampling failure records; there is no
client-supplied correlation identifier in audit output.

Fixed typed event/outcome pairs cover service start/ready/stop/failure,
default/validated/rejected configuration, IPC startup success/rejection,
authentication failure, rejected request, explicit ADMIN denial, authorized
STATUS/HEALTH requests, transport failure and sampling failure. Authorized
means the decision was made, not that a response reached a client. Unknown
operations are denied and categorized as request rejection. Requests refused
by filesystem DAC before reaching the daemon cannot be observed here.

No raw request bytes, correlation IDs, arbitrary error strings, config
paths/contents, tokens, credentials, LAN identifiers or packet contents are
serialized. Numeric Unix identities and timestamps are sensitive local
metadata: keep audit files private, out of public CI and source archives.

## Bounds and failure policy

Single-writer, no queues/threads, fixed formatting buffers and 1 MiB total
per session. Each record is checked against the remaining byte budget,
file type/owner/mode/link count and expected file size, then appended and
fsynced before success is reported. A short write, sync failure, invalid
record, exhausted budget or file metadata mismatch makes the sink sticky
failed. No retry after ambiguous writes, no silent fallback. When enabled,
record authorization before sending a response; on audit failure deny the
pending response where possible, terminate the daemon with exit 6, emit a
fixed stderr audit-gap message and clean up its IPC socket. A transport
failure after an authorized response attempt is separately recorded. A
partial final record is possible on a write failure; preserve it as evidence
of an incomplete session, not a valid record. SIGXFSZ is ignored in audited
mode so file limits return a reportable error. A crash or power failure can
leave a session without a stop record; fsync is not a guarantee against all
storage failures.

The cap bounds one session, not aggregate storage across operator-created
directories. Synchronous filesystem operations may stall; no hard I/O
latency guarantee. A same-UID or root actor can modify or remove evidence,
rename directories or replace paths; checks are not a cryptographic integrity
scheme or a protection from a hostile filesystem. No encryption, authenticated
remote sink, multi-process journal, retention policy, signed chain, automated
rotation, audit reader IPC or administrative RBAC is implemented. Future
storage and deployment milestones must address these before release.

## Verification

```bash
python3 scripts/verify_m25_audit.py --build-dir build/presets/linux-release
```

Mandatory compiled and live tests cover bounded records and file capacity,
invalid event/sticky failure, protected creation and existing entry rejection,
configuration and service events, identity and authorization, redaction,
real file-size-limit write failure, response denial and cleanup. Cross-UID
runtime tests are conditional on a harness able to change identity; a normal
unprivileged runner reports NOT_APPLICABLE for that subcase. Source checks
are not runtime evidence. Expected CTest counts: 23 desktop normal, 20 desktop
sanitized, 15 core-only normal and 16 core-only sanitized.

M2.6's configured desktop health polling consumes one audit authorization
record per successful query when auditing is enabled. See
[desktop health](DESKTOP_HEALTH_M26.md) for cadence and capacity limitations.

M2.7's explicit systemd profile requires auditing and creates a fresh private
session directory on each start; no previous evidence is overwritten or deleted.
See [systemd service integration](SYSTEMD_SERVICE_M27.md). Aggregate quota and
retention remain deferred, and automatic restart is disabled.

## M4.7 extension

The read-only [agent roster query](DESKTOP_AGENT_MANAGEMENT_M47.md) records
`agents_authorized` before responding when the audit sink is enabled. Endpoint
identifiers, pins and paths are excluded from records.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M4.7 — Desktop enrollment and agent management

## Scope and authority

The Assets page shows a genuine, read-only manager-selected enrollment roster.
It does not read registry files directly, infer an agent from a local IP address,
create credentials, or trust a discovered device. The existing seven-section
navigation, desktop-owned lifecycle and deny-only deployment remain unchanged.

The manager accepts the optional development argument `--enrollment-dir ABS_DIR`
only alongside `--ipc-dir`. The operator must choose trusted path ancestry and an
existing owner-only (0700) directory; final symlinks and unsafe ownership/modes
are rejected before readiness. The manager retains the directory descriptor and
uses the existing M4.4/M4.5 full registry validation and nonblocking lock on every
query. It does not implicitly initialize a registry or use a desktop-selected
path. If an explicitly selected directory is renamed, the retained descriptor
continues to identify the original directory until restart. Missing, busy,
corrupt or unsafe storage returns unavailable, never a successful empty roster.

This is local development inspection, not a deployed RBAC interface. The
existing `knetsentry-enrollment` owner-authorized CLI remains the only supported
administrative mutation path. It requires independently verified identity pins.
The desktop cannot approve, rotate or revoke an identity over IPC. The systemd
launcher and GUI-owned manager launch do not automatically select a registry.

## Wire contract (I-01 / I-23, TB-05)

The read-only request is `KSIPC/1 AGENTS <16 lowercase hex request ID>\n`.
The existing 4-byte big-endian length framing, 64-byte request limit, same
UID/GID `SO_PEERCRED` checks and bounded exchange deadlines remain in force.
`STATUS` and `HEALTH` retain their exact existing wire schemas and bounds.
The response is one of:

```text
KSIPC/1 OK 0123456789abcdef AGENTS UNAVAILABLE
```

or a `KSIPC/1 OK <request ID> AGENTS READY\n` header followed by zero or more
35-byte records: `A <32 lowercase hex endpoint ID>\n` (approved), or
`R <32 lowercase hex endpoint ID>\n` (revoked). Maximum 128 unique endpoints,
4,608 bytes total; duplicates, zero IDs, unknown status flags, truncated records,
trailing data and wrong request IDs are rejected by the client. The wire carries
no fingerprint, certificate, private key, path or remote counter. Multiple
retired keys for a rotated identity collapse to one approved row when a current
key exists; revoked IDs are distinct from retired credentials. Authorization
is audited as `agents_authorized` before response when the protected audit sink
is configured, without inventory values. The extra periodic query consumes
audit capacity; the existing bounded audit sink and fail-closed full-sink
behavior are unchanged. Administrative IPC remains denied.

The storage implementation is compiled separately from TLS-backed admission.
The manager and desktop's service library link only the registry storage target;
no operational TLS or agent-health library is linked into either executable.

## Presentation semantics

The Assets page includes registry availability, approved identities, revoked
identities, pending enrollments, certificate status, agent connection health,
and administrative authority. The C++ model queries the manager after a valid
health response using a separate bounded nonblocking exchange. Previous roster
values are cleared on refresh or directory change, and unavailable/invalid
responses never leave current rows visible. With the usual 30-second cadence,
loss is detected on the next refresh, not instantaneously. The two queries
are independent same-UID snapshots, not an atomic combined status transaction.

An explicitly initialized empty registry displays no identities. A disconnected,
unconfigured or unreadable registry displays unavailable instead of zero.
Pending enrollment requests, certificate observations and operational agent
sessions are not collected or published by the current manager, so their cards
explicitly report unavailable. No approved identity is shown as connected,
certificate-valid or monitored. The local daemon heartbeat is not agent health.
Registry IDs are potentially sensitive inventory metadata: keep screenshots and
logs with real IDs private. No IDs or pins are added to diagnostic messages.

## Installed development service qualification

M4.7 changes the manager executable even though the unit and launcher remain
unchanged. Refresh the reviewed root-owned installed binary before requesting
live systemd acceptance; see [systemd development service](SYSTEMD_SERVICE_M27.md).
The verifier must continue rejecting stale deployed binaries. Registry operations
also explicitly reject failed directory reopens before locking or inspecting
storage; the enrollment contract exercises non-directory and closed descriptors.

## Synthetic verification

From the project root, use an isolated private fixture (no real credentials):

```bash
ctest --preset linux-release -R '^knetsentry_agent_roster_(contract|runtime)$' --verbose
```

The mandatory tests verify the maximum roster codec, malformed and duplicate
records, read-only peer role, actual manager/CLI approval, rotation, revocation,
missing, unsafe, busy and interrupted storage, denied mutations, audit privacy
and shutdown. The existing full-desktop GUI integration additionally exercises
actual approved/revoked identities, disconnection and unconfigured restart;
the Qt model and navigation regressions check read-only properties and visibility.

This is partial implementation of issue #40. Actual pending-request intake,
certificate status and live agent health publication, and an independently
authorized GUI administrative workflow are not implemented. Do not mark the
entire issue accepted until its intended scope is explicitly resolved and those
remaining capabilities are implemented or scheduled as separate approved work.

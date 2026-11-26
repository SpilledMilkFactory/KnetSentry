<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M5.4 — Linux Audit-event integration

Issue #45 extends C-08/P-08 with opt-in journal-mediated Linux Audit records.
The native systemd API selects `_TRANSPORT=audit` and, in production, the local
`_MACHINE_ID`. This is an already-readable local journal source, not a direct
kernel audit subscription or auditd log-file reader. No audit rules, socket
activation, audit daemon configuration, capabilities, group membership, or
journal permissions are changed. The existing non-root startup policy applies.

## Configuration and missing facilities

```bash
umask 0077
state=$(mktemp -d "$HOME/ks-audit-m54.XXXXXX")
./build/presets/linux-release/apps/agent/knetsentry-agent \
    --run --schema-version 1 --collectors audit --state-dir "$state"
```

The audit mode has a fixed source selection; no `--unit` or arbitrary file path
is accepted. Readiness means that the local collector started, not that kernel
Audit is enabled or that complete audit visibility exists. An empty readable
selection is nonfatal and reports `no new readable audit records; coverage=unknown`.
The agent remains available for later records and shuts down normally on SIGINT
or SIGTERM. It reports observed batches without printing event values. An
explicit source-open/read error or unavailable saved cursor stops collection
with a fixed diagnostic and a nonzero exit status, preserving committed state.
The empty selection cannot distinguish absent audit facilities, unreadable
journals, journal retention, or a quiet source. Never change privileges to
force a positive result. Direct auditd files, NETLINK_AUDIT, and privileged
helpers are outside this milestone.

## Records and privacy

`audit-m54.v1` uses header `KNETSENTRY-AUDIT-V1<TAB>audit` and eight tab-separated
fields: native cursor, journal realtime and monotonic microseconds, machine ID,
boot ID, fixed source `audit`, decimal `_AUDIT_TYPE`, decimal `_AUDIT_ID`.
The fixed source marker is not a service unit. Audit record type values in
1000–65535 and nonzero unsigned 64-bit IDs are accepted; malformed or missing
structured fields fail closed. Unknown numeric types in that range are retained
without assigning a semantic meaning. Audit IDs are correlation hints within a
boot, not unique record keys: multipart events may share IDs, so deduplication
uses exact journal cursors. This is record-level collection, not full event
assembly, syscall interpretation, or verification of audit outcomes. Receipt
realtime is not necessarily the original kernel audit timestamp.

No MESSAGE, command line, executable, path, account, credentials or arbitrary
payload fields are requested by audit mode. Retained identifiers and timestamps
are still private. Do not share actual state or snapshots. Journal metadata is
source-reported, not cryptographically authenticated evidence.

## Persistence and recovery

The existing M5.2 protected state directory (0700), private regular files
(0600), descriptor-relative access, symlink and hard-link checks, cooperative
writer lock, pending transaction, file/directory fsync and exact cursor recovery
are reused. Separate `audit-m54.pending` and `audit-m54.v1` files preserve earlier
journal and authentication formats. Limits remain 16 records/batch, 128 records,
256 KiB, 1024-byte cursor. No eviction or approximate cursor fallback. A new
empty selection creates no committed record file. Capacity exhaustion is a
terminal diagnostic, not a reason to discard committed records. Rotation gaps,
late insertions, same-UID tampering and production spool/delivery qualification
remain outstanding.

## Verification

`knetsentry_audit_collection_contract` runs in all seven presets. Its genuine
native synthetic journal has three selected records and one excluded syslog
record with audit-like fields. Two selected records share an audit ID. It checks
structured type/ID and timestamp retention, privacy, exact recovery, duplicate
prevention, invalid state, empty selection and explicit source failure. The
second native fixture omits a required audit ID and verifies terminal failure
without checkpoint advancement, including restart. Each
SHA-256-checked fixture was generated with a disposable systemd 257 writer;
no private writer ABI or runtime binary ships. CLI negative cases reject unsafe
configuration before source access. No actual host audit stream is read by
mandatory CI. Existing journal/authentication regressions remain mandatory.

For live verification use only existing authorized access, report fixed
messages and aggregate counts; zero records is unknown visibility rather than
an affirmative collection result. No new dependencies. Existing DEP-008 shared
libsystemd development scope is unchanged. See systemd journal-fields(7) and
systemd's journald-audit.c for the source field definitions.

## Maintainer acceptance

105 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED and all 343 configured CTests passed
on Ubuntu 26.04; nine hosted checks and reported manual GUI/merge succeeded.
Live audit-mode output was not supplied; no positive live audit count is claimed.
The optional M5.5 outbox extends local-only collection without changing the
original audit file format; see [M5.5](TELEMETRY_DELIVERY_M55.md).

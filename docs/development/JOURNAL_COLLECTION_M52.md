<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M5.2 — systemd journal collection

Issue #43 introduces explicit local, metadata-only journal collection in C-08/P-08.
It does not activate a privileged helper, transport, monitoring consent, a receiver,
production evidence repository or event spool. M5.1's empty-collector mode and
startup privilege checks remain unchanged.

## Configuration and data minimization

Development use requires an operator-authorized source and a deliberately selected
local state directory (existing, owned by the current ordinary user, mode 0700,
no symlink components). Do not use a production evidence directory or the source
checkout. Use a durable local filesystem for restart persistence; tmpfs is for
fixtures only and is not reboot-durable. No account, group, service or filesystem
permission changes are performed automatically.

```bash
state=$(mktemp -d "$HOME/ks-journal-m52.XXXXXX")
./build/presets/linux-release/apps/agent/knetsentry-agent \
    --run --schema-version 1 --collectors journal \
    --unit systemd-journald.service --state-dir "$state"
```

Choose a unit that the current user is authorized to read. The example is not a
requirement to gain journal-wide privileges. Only one literal `.service` name
(up to 128 ASCII characters; no glob, slash or control character) is accepted.
The native API opens the local journal and matches `_SYSTEMD_UNIT` exactly;
records must also have the local `_MACHINE_ID`. No environment-configured
remote source or arbitrary journal file is exposed in the agent CLI. A fixture
reader opens an isolated explicit directory only in tests.

The collector retains the journal cursor, receipt realtime in microseconds
since the Unix epoch, monotonic microseconds relative to the associated boot,
record machine ID, boot ID and system unit. Clock values are not rewritten;
monotonic values are not comparable across boots. These fields are provenance
claims of the local journal, not cryptographic evidence that a host is trusted.
The journal's `MESSAGE`, command lines, environment, raw payloads and arbitrary
fields are not requested or retained. Metadata and cursor remain sensitive and
must not appear in public CI output or uploaded acceptance logs. Readiness is
not evidence of source visibility: an empty result can mean no matching entries
or insufficient journal permissions; no complete coverage claim is made.

## Durable development checkpoint

The single protected `journal-m52.v1` file is a bounded development evidence
snapshot with header `KNETSENTRY-JOURNAL-V1<TAB>unit` and newline-delimited
six-column TSV rows: cursor, realtime_usec, monotonic_usec, machine_id, boot_id,
unit. The last committed row is the checkpoint. No independent cursor file can
advance without the corresponding record. Cursor length is limited to 1024
printable non-space ASCII bytes, IDs to 32 lowercase hex digits, and record
fields are validated on read and restart. Realtime must be positive; both
timestamp values must fit within the native journal timestamp domain (<2^55 microseconds). The state holds at most 128 records
and 256 KiB; at most 16 records are processed per poll, followed by a one-second
signal wait. This is a deliberate development limit, not the future spool.

Each update writes a private exclusive temporary file (`journal-m52.pending`),
fsyncs it, atomically renames it over the previous committed state, then fsyncs
the directory. A verified private leftover pending file from a crash is discarded
under the directory lock. A crash after rename has a complete old or new state
under the supported local filesystem semantics; power-loss qualification remains
outstanding. Errors stop collection, including a failed post-rename durability
barrier (the new record may already exist). A nonblocking exclusive directory
lock prevents cooperating concurrent writers. Descriptor-relative opens reject
symlinks, unexpected owners/modes, non-regular files and hard links. The final
filesystem class must be ext4, XFS, Btrfs, tmpfs or overlayfs; this is not full
mount-identity or physical-volume qualification. The selected parent path must
be trusted and local. Same-UID or privileged tampering is not prevented by mode
bits and cooperative locks; no cryptographic tamper-resistance is claimed.

With no committed state, collection starts at the head of the selected readable
journal. Every subsequent poll and restart uses `sd_journal_seek_cursor`,
`sd_journal_next` and `sd_journal_test_cursor` to validate the exact last entry
before moving forward. The nearest-entry behavior of seek alone is not accepted.
If retention, rotation or corruption makes the cursor unavailable, stop with a
fixed diagnostic, preserving committed data. Duplicate cursors, unexpected units,
malformed fields and exhausted capacity likewise stop without skipping or deleting
records. Missing state in a newly selected directory is a new collection; there
is no automatic reset, retention, forwarding, historical-gap reconstruction, or
lossless guarantee for late entries inserted before the checkpoint. Do not delete
a checkpoint to hide a gap. Review and archive it privately; a new state directory
is a deliberate new capture with possible overlap. Batches are bounded by record
count, not a hard deadline for library/filesystem I/O.

## Dependency decision (DEP-008)

Scoped development use of Ubuntu 26.04 distro-provided shared `libsystemd` via
`libsystemd-dev` and pkg-config. The systemd upstream project is
https://github.com/systemd/systemd; the library is predominantly LGPL-2.1-or-later
with component-specific notices (inspect `/usr/share/doc/libsystemd0/copyright`
and the corresponding source package). The existing external systemd dependency
is extended to native journal reads; no copied library sources or vendored binaries,
no new service activation, networking or package redistribution. Record resolved
package versions in CI and local acceptance. No exact Ubuntu package version or
recursive license/security clearance has been established on this revision;
maintainer review of the installed version and distro security updates is required.
This is a scoped build decision, not APPROVED_FOR_DISTRIBUTION; release SBOM,
transitive licenses, notices and vulnerability review remain separate gates.

References: https://www.freedesktop.org/software/systemd/man/latest/sd-journal.html,
https://www.freedesktop.org/software/systemd/man/latest/sd_journal_seek_cursor.html,
https://www.freedesktop.org/software/systemd/man/latest/sd_journal_get_cursor.html.

## Qualification and limitations

The mandatory CTest `knetsentry_journal_collection_contract` exercises synthetic
source records, timestamp/provenance retention, restart, stale cursor, duplicate
cursor, scope mismatch, interrupted pending-state cleanup, locking, file modes,
symlink/hardlink denial, malformed state and capacity. It also uses the native
systemd adapter on empty and populated isolated journal directories, not the
host journal. The populated fixture contains three synthetic records (two
selected, one excluded), fixed timestamps and IDs, and message canaries. It is
encoded as gzip/base64 data with an SHA-256 check in `tests/journal_fixture_m52.py`.
The fixture was generated with the installed systemd 257.9 journal writer
(using its version-specific private ABI only in the disposable generation
process), verified with `journalctl --verify`, and checked for absence of actual
sandbox machine/boot IDs. No private ABI, generated executable or library is
shipped or used during build, runtime or CTest. The test checks exact resume from
an earlier committed row, repeated restart, missing cursor, filtering, metadata
and message exclusion. The existing M5.1 process test exercises rejected journal
CLI arguments and a missing state path in addition to original process checks.

An optional semantic regeneration/qualification test is provided for a host that
already has a trusted `systemd-journal-remote` import executable available; it
uses only local synthetic export input, does not start a daemon, and never
listens on a socket. Do not install or enable a remote journal service merely to
run this test. The optional import tool is not a build or runtime dependency.

```bash
python3 -B scripts/check_m52_native_fixture.py \
    --binary build/presets/linux-release/tests/knetsentry_journal_test \
    --import-tool /usr/lib/systemd/systemd-journal-remote
```

An authorized target-host manual test must additionally demonstrate real selected
records, matching timestamps/provenance, a clean stop/restart without duplicate
cursor or prior record loss, and no message bodies. Do not print records into
acceptance logs. The private development state may be inspected locally only.
No complete Ubuntu target-host, production service,
source availability, power-loss, raw-store or release-security qualification is
claimed before the corresponding evidence is available. Relevant partial evidence:
TV-13 (source loss), TV-25 (diagnostics privacy), TH-033; no threat closure claimed.

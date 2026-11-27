<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M6.10 — Independently approved raw and indexed storage

Issue #148; bounded opt-in library foundation, target qualification pending.
This does not replace the M6.4 development database or operational receipt sink.

## Configuration and trust

`LocationApproval` captures the explicit absolute directory, current boot ID,
unique Linux statx mount ID, device, inode, filesystem class and statfs filesystem
ID. The trusted caller must retain and compare the approved snapshot, not
silently approve the currently visible path on every operation. Approval is
boot/mount scoped; reboot or remount requires explicit renewed approval. statfs
identity is not a verified filesystem UUID; persistent administrator approval
storage and cross-boot UUID verification remain outstanding.

`SplitStorageConfig` independently selects raw and index directories, existing
bounded StoragePolicy and a minimum available-byte reserve (default 1 MiB).
Both directories must already exist, be owned by the effective service UID and
be mode 0700. Same directory, aliases, nested lexical paths, symlinks and
unsupported filesystems are refused. Separate directories on one filesystem
are allowed; distinct local filesystems are supported by the interface. ext4,
XFS, Btrfs and F2FS are allowlisted, subject to required operation support;
explicit development overlay permission exists for synthetic CI fixtures only.
No network filesystem, tmpfs or implicit OS-disk fallback is authorized.

The library holds exclusive advisory directory locks and descriptors, checks
both descriptor and freshly resolved pathname identity, and checks opened file
mount IDs. openat2 forbids symlinks and magic links during directory selection and mount crossings during evidence-file opening.
Every write uses the held directory descriptor; the only procfs link use is
publishing the already-open anonymous temporary inode. No SQLite path resolution
or SQLite sidecar creation occurs on the independent volumes. The trust model
assumes a trusted kernel, procfs and service UID, not protection against root or
another malicious process running as that UID. O_TMPFILE and directory fsync
must succeed; there is no weaker fallback. A detach concurrent with a write can
leave bytes on the original pinned mount, never redirect the write to the
underlying directory; a failed final revalidation reports no durability.

## Raw-first protocol

`CreateNew` requires two empty dedicated directories; `Existing` requires an
existing paired store. No implicit migration, reinitialization, relocation or
repair is performed. Initialization writes a random 128-bit pairing ID and raw
head, then the paired empty SQLite image. Partial initialization fails closed.

`append` uses the existing canonical parsing, duplicate identity and bounded
admission reference. Each minimized original segment contains pairing ID,
monotonic store ID, trusted receiver time, collector, configured binding, source
and canonical bytes with a domain-separated SHA-256 commitment. The segment is
written to an anonymous O_TMPFILE inode (0600), synced, linked without overwrite
into the approved raw directory and followed by directory fsync. The prefix
head (record count and SHA-256 of the ordered commitments and pairing ID) is
then atomically replaced and synced before a durable result is returned.

A single valid trailing segment beyond the verified committed head can be
recovered by explicit Existing activation or append retry after sync; no read
reports that incomplete state as indexed or complete. A visible abandoned
`.pending` file, missing committed record, malformed record or mismatch refuses
access; no implicit deletion. A head and all its records remain unkeyed, so
coordinated replacement or whole-store rollback is not prevented. A previously
observed prefix and indexed-ID set are also checked within a live instance.

Index failure does not prevent bounded raw admission in an already activated
instance. Raw failure prevents durable raw acknowledgment. New activation
requires both paired locations. No automatic spool, default path or deletion.
A durable library return is not an operational transport ACK.

## Independent index

`index(id)` verifies the raw prefix and syncs the selected raw file and directory
before writing an independent SQLite projection. The image stores pairing ID,
record ID, original digest, source unit, collector, trusted receipt and source
times, class, outcome, activity and mapping. It contains no original canonical
row, native cursor, machine/boot ID or full binding. The normalized projection
is built in a bounded in-memory SQLite transaction with a fixed schema and an
index on source/mode/outcome/time/ID, serialized, and published using a synced
anonymous file and descriptor-relative atomic rename. A failed publication
leaves original evidence intact; the previous complete index survives failures
before rename. A visible abandoned projection pending file refuses queries.

The image is opened from bounded bytes with sqlite3_deserialize read-only;
defensive mode, disabled extensions, trusted_schema off, fixed schema, pairing,
integrity_check and every projection row are checked against original evidence.
The current bounded search and pending-page API reconstructs a reference view
from verified raw and indexed IDs. This is not an optimized direct SQLite
query planner or GUI integration. The 128-record ceiling, wire quota, bounded
SQLite page quota and free-space reserve checks apply. The reserve is a snapshot
preflight, not filesystem-enforced reservation; it does not account for every
allocation or concurrent external writer. Nonzero retention age is rejected instead of silently ignoring configured cleanup. No retention or hold mutation API is
exposed for this new store; existing M6.7 retention is unchanged. Full volume
health reporting, operational integration, production scale, retention/holds,
protected trust anchors, encryption at rest and controlled relocation remain
outstanding.

## Verification

`knetsentry_split_storage_contract` runs in all seven configurations: actual
private files and SQLite image, invalid mount/boot/filesystem approval, unsafe
permissions, symlinks, competing owner, path substitution, raw-first visibility,
index outage, exact retry, restart, committed head and recovery-window fixture,
wrong index pairing, projection tampering, quota refusal and isolated child
RLIMIT_FSIZE failures. The recovery-window fixture reconstructs the state, not
a timed crash injection. All records are synthetic.

```bash
ctest --preset linux-release -R '^knetsentry_split_storage_contract$' --verbose --no-tests=error
```

Optional privileged qualification (required for the mount gate):
`sudo build/presets/linux-release/tests/knetsentry_split_storage_test --mount-fixture`
creates a private mount namespace, marks propagation private, binds a disposable
source directory, detaches and rebinds it and verifies refusal without fallback.
The fixture changes no host mount or service configuration. It is not a test on
two physical devices. For distinct filesystems, as an ordinary user, pass two
new empty private directories on already mounted supported local filesystems:
`knetsentry_split_storage_test --two-volumes RAW INDEX`. It deliberately retains
the synthetic files for review; do not point it at real evidence directories.
No actual volume is formatted, mounted or filled by that mode.

Target CTest inventory: 477 across seven presets, 62 structural verifiers;
137 consolidated gates when the mount fixture and preceding privileged gates
are explicitly requested. Genuine mount and distinct-filesystem qualification
are pending. No production deployment or complete issue closure is claimed.

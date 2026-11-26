<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M5.6 — Initial file integrity monitoring

**M5.7 compatibility update:** The historical commands and state layouts below
precede mandatory `--privacy-policy` configuration. Use the current
[M5.7 contract](PRIVACY_MINIMIZATION_M57.md) for active collector invocations,
redaction and policy-bound journal state. Do not reuse legacy unbound state.

Issue #47 establishes an opt-in local polling collector in C-08/P-08.
It does not grant monitoring consent, operational network authority, privileged
file access, or a production evidence pipeline. No new dependency is required;
SHA-256 uses the existing distribution-provided OpenSSL Crypto library under
DEP-005. Its scoped build approval is extended to file hashing; no bundled
redistribution or release dependency clearance is granted.

## Explicit selection and resource limits

Run the ordinary unprivileged agent with an explicitly approved list:

```sh
knetsentry-agent --run --schema-version 1 --collectors fim --path /absolute/file --path /absolute/other
```

One to eight unique absolute paths, at most 1024 bytes each, components at
most 255 bytes, ASCII letters/digits/dot/underscore/hyphen only. No empty
components, dot or dot-dot segments, patterns, relative paths, directory
scans or recursive traversal. Parent directories must exist at startup;
individual leaf files may initially be absent. Paths are visible through
permitted process argument inspection; never pass sensitive path names in
public evidence. Existing collector modes remain unchanged. FIM does not
accept `--buffer-for` or `--state-dir` and creates no state files.

Each file is limited to 1 MiB (including sparse logical size), up to 8 MiB
of content read per scan, in 16 KiB chunks. Polls wait one second between
completed scans. A scan reports at most eight changes. The limits bound bytes
and work count, not kernel I/O latency; stalled local storage or blocked
stdout can delay processing and shutdown. The implementation does not use
recursive enumeration, inotify queues, subprocesses or network sockets.

## Safe resolution and observation

The existing agent root/capability rejection, inherited-capability removal,
no-new-privileges, umask and signal handling precede filesystem inspection.
Linux `openat2` resolves only explicit path components, with beneath and
no-symlink/no-magic-link restrictions. Local filesystem classes are restricted
to ext, XFS, Btrfs, tmpfs and overlay; no content access on unapproved classes.
Explicit ancestor mount boundaries on allowed filesystem classes can be
traversed, but the monitored leaf cannot cross a mount boundary. A pinned
parent descriptor prevents directory inode reuse during a session; the
configured parent path is resolved and compared before and after observation.
The kernel's own proc descriptor directory is used only to reopen an already
validated O_PATH regular inode, not a caller-provided path. No fallback to
ordinary unsafe path opens when openat2/procfs is unavailable.

The leaf must be a regular, single-link file within the size limit. Symlinks,
hard links, directories, FIFOs, devices, sockets, unreadable files and unsafe
parent replacements reject startup or terminate polling. An absent leaf is a
valid observation only if the configured parent still resolves to the pinned
identity. The collector checks identity, mode, ownership, size, link count,
mtime and ctime before and after reading, and revalidates the named leaf.
Unstable observations or failed reads terminate with coverage unknown rather
than emitting misleading changes. No access-time comparison (reads can update
atime). The monitor does not claim immunity to a malicious same-UID/root writer,
concurrent rename races, mount namespace manipulation or filesystem corruption;
its purpose is bounded monitoring of explicitly approved local paths, not a
sandbox against hostile filesystem administration.

## Baseline and reporting

Initial snapshots retain metadata and SHA-256 in process memory only. No
baseline event is emitted. The next complete successful scan compares each
slot with its previous snapshot and replaces it. Precedence: created/deleted,
then inode/device replacement, then content digest, then metadata changes
(mode/owner/group/size/mtime/ctime/link count). No event for unchanged files.
If multiple attributes change, only the highest-priority category is emitted.
Example fixed diagnostic (slot is one-based configuration order):

```text
knetsentry-agent: fim change; slot=1; kind=content-changed
```

The raw content, digest, path, owner IDs and inode numbers are not emitted
or persisted. The agent emits fixed errors for unavailable baseline and
unsafe/unstable observation, with exit 1; invalid configuration exits 2.
The process reads authorized file contents transiently; OS page cache,
process inspection, swap/core dumps and atime are outside this privacy claim.
This is polling, not a lossless historical event stream: transient changes
between snapshots can be missed, inode reuse can obscure replacement, and
no comparison across restarts is provided. There is no persistent baseline,
FIM outbox format, remote delivery, indexed event, alert, ACL/xattr measurement,
or GUI integration. These are separate future responsibilities.

## Verification

`knetsentry_file_integrity_contract` launches the actual agent under an
ordinary user against disposable synthetic files. It exercises content
changes with unchanged size/mtime, metadata changes, replacement, deletion,
creation, two independent slots, unchanged and unapproved sibling behavior,
configuration limits, symbolic/hard links, FIFOs, oversized files, unsupported
filesystem, parent substitution, fixed diagnostics, empty capabilities,
no-new-privileges and clean shutdown. A kernel inotify canary watch verifies
that the unapproved alias target is not opened/read (positive control first).
The regression also checks the 8-path and 1-MiB inclusive boundaries and
unreadable-file rejection. Mandatory CI does not inspect actual
host security files or grant privileges. The structural verifier checks
registration, not runtime security; full Ubuntu acceptance remains required.

## Maintainer acceptance (2026-11-26 UTC)

109 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED; 357 CTest executions, nine hosted
checks (`06fb6d8`) and manual synthetic FIM changes, unsafe substitutions,
clean shutdown, installed manager comparison and reported GUI verification
passed. Existing desktop diagnostics recurred; no production confinement or
complete historical monitoring qualification is claimed.

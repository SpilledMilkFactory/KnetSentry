<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Storage Placement and Raw-First Event Contract

**Issue:** M0.5. **Status:** architecture and future acceptance requirements;
M6.3 supplies a volatile reference interface and M6.4 supplies a development SQLite backend; M6.10 adds a bounded independent raw/index library foundation, not an operational storage selector or Qt configuration UI.

## Configuration model

| Role | Directory selection | Intended process authority | Default placement policy |
| --- | --- | --- | --- |
| Allowed original event / raw segment repository | Administrator chooses a local mounted directory through Qt GUI or authorized CLI | Restricted manager storage writer | Explicit first-run selection or documented protected default; user can move to another local drive |
| Normalized/indexed SQLite database, WAL, SHM and temp | Independently configurable directory on a qualified local filesystem | Restricted manager database writer | Protected service location, changeable independently |
| Bounded source/ingress spool | Dedicated explicitly configured protected quota/path | Relevant restricted producer/service | No implicit OS-disk fallback for absent raw store |
| Configuration, identity, audit control records | Hardened service-managed path | Specific authorized services | OS-managed by default, never silently treated as raw-event storage |
| Optional raw packet payloads / PCAP | Separate approval, location, retention, permissions | Privileged capture policy + unprivileged worker | **Disabled by default**; selecting raw *event* location does not enable packet payload capture |

No GUI component writes to storage directly. The GUI may browse using Qt Quick
Dialogs / an appropriate native Qt dialog under GNOME and KDE; the manager must
independently verify the chosen path with its actual identity, mount namespace,
permissions and configured storage policy before accepting a change. A file
browser's visibility alone is not authorization or proof of service access.

## Ordered pipeline

1. A bounded telemetry source envelope is received with a source identity,
   observation scope, provenance, data classification and stable record ID.
2. Scope, message length, data-class permission and privacy/redaction rules
   are validated before storing anything. Prohibited payloads are not saved.
3. Permitted original bytes and integrity/provenance metadata are appended to
   a segment on the **approved raw volume**. Commit and durability barrier are
   completed according to the declared acknowledgment contract.
4. Raw segment state is `RAW_DURABLE`; pending normalization is recorded as
   `INDEX_PENDING` until a separate normalized SQLite transaction commits.
5. The query view reports `INDEXED` only after the indexed record is
   committed and visible. A failed index remains a replayable raw record with
   explicit degraded/lag status, not a silently missing event.
6. Retention and legal-hold operations are separately authorized and preserve
   the relationship between immutable-original evidence and normalized data.

The exact binary format, checksums, commit/sync mechanism and replay protocol
will be decided and tested in M6; this architecture makes no unsupported
power-loss durability claim. A full-packet capture is not implied by step 3.

## Mount identity and filesystem safety

- Record a stable expected volume identity (e.g. verified filesystem UUID or
  other suitably validated stable identifier) **plus** canonical directory,
  configured mount, service permission and filesystem class.
- Check effective target mount/identity at activation, service start, change,
  and each new segment; guard against symlink and mount-point substitution
  during file creation with descriptor-relative operations and revalidation.
- Never infer a volume from a pathname alone: after an unmount, the empty
  mount directory may resolve onto the OS filesystem. This must **not** be an
  implicit fallback or an accepted write target.
- Reject unsafe ownership, permissions, special files, path traversal,
  unsupported locking/durability behavior and unsupported network mounts.
- Support safely mounted local secondary disks; removable storage requires
  explicit acknowledgment of disconnect risks and appropriate protection.
- An independently approved bounded spool can absorb temporary faults, but
  only if its path, quotas, confidentiality and failure consequences are
  configured in advance. Otherwise reject new durable writes and alert.
- Display both raw and index volume health and depletion forecasts.

## Recovery and relocation

The manager must authorize configuration edits, preflight the new target, size
available capacity and reserve, and transition through a controlled segment
rollover/copy/verify/switch/cleanup procedure with recoverable rollback. Keep
the prior store authoritative until integrity checks and a durable cutover
complete. Preserve held evidence and append-only audit records; never assume
cross-filesystem rename is atomic. Expose progress/error and forbid racing
uncontrolled writer activity.

## Future ownership and acceptance

- M6.3–M6.5 and M6.10: secure raw store, independent indexed database, raw-first commit,
  durability states, volume validation and incident evidence IDs.
- M6.7/M14.3: per-volume retention/quota/reserve and no-silent-loss rules.
- Proposed M8.10: Qt 6/Kirigami folder selection, mount health, permission preview and
  independent storage path settings with role-checked manager IPC.
- M14.4/M14.6: removable-disk failures, recovery, storage migration and audit.
- M13.6: security checks for mount substitution, path races and permissions.
- M14.1: same-volume and separate-volume benchmark comparison on real media.

Trace to `KS-PERF-041`–`KS-PERF-054` in
[performance requirements](../development/PERFORMANCE_REQUIREMENTS.md),
[benchmark BT-22–BT-28](../development/BENCHMARK_PLAN.md), and
[fault cases F-13–F-18](../development/RELIABILITY_RECOVERY_PLAN.md).

## M6.3 reference boundary

The [storage abstraction](../development/EVENT_STORAGE_M63.md) separates raw
admission from index visibility and exposes explicit durability. The reference
backend never reports RAW_DURABLE or participates in authenticated ACKs.
KS-PERF-041/043–046, mount/device authorization, protected durable segments,
separate index placement, replay after restart, relocation and quotas remain
unqualified operational requirements; no fallback path is introduced.

## M6.4 development SQLite boundary

The [SQLite backend](../development/SQLITE_STORAGE_M64.md) retains minimized
KSTD rows and their indexed projection in one dedicated development database.
Separate transactions exercise raw-before-index visibility and restart; this
is not the approved independent raw-segment/index-volume deployment. The
backend is not a ReceiptSink. No production volume configuration is activated.

M6.5 adds record-level integrity metadata to the existing development SQLite
store; it does not replace independently authorized production raw/index volumes.
See [integrity model](../development/EVIDENCE_INTEGRITY_M65.md).

M6.6 adds source/mode/time indexes and verifies existing evidence during schema
migration; independent approved raw/index placement remains outstanding.
See [search contract](../development/EVENT_SEARCH_M66.md).

M6.7 bounds logical admission and the SQLite main-file page allocation using
caller-supplied limits, exposes warnings and reusable pages, and preserves
explicit retention/holds. This does not establish a total per-volume disk quota
or independent production placement and reserve enforcement.
See [retention contract](../development/STORAGE_RETENTION_M67.md).

M6.8 permits explicitly selected existing schema-v4 development stores to be queried through the foreground manager. The desktop never opens SQLite. This read-only query interface does not approve production raw/index placement or implement independent filesystem-enforced read-only storage access. See [M6.8](../development/EVENT_EXPLORER_M68.md).

## M6.10 split-storage foundation

See [M6.10](../development/SPLIT_STORAGE_M610.md). Separate approved directories, descriptor-relative immutable raw segments and a paired bounded SQLite projection implement an opt-in library foundation. Current approvals are boot/mount scoped; persistent UUID validation, actual distinct-volume qualification, operational integration, retention and relocation remain outstanding.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# ADR-0005 — Separate, Administrator-Selectable Raw Evidence Storage

**Status:** Accepted as an M0.5 design requirement; implementation pending.

## Context

A LAN SIEM can accumulate large raw event archives. Administrators must be
able to place the raw evidence repository on another mounted local drive,
independent from system installation and independently from indexed SQLite
storage. Removable media introduces mount substitution and durability risks.

## Decision

Expose separate raw and indexed storage targets through a Qt-based graphical
folder chooser and authenticated manager configuration. Make the raw evidence
store configurable on locally mounted, qualifying volumes. Persist permitted
original events before normalization/indexing, record independent durability
states, and never silently spill missing external-volume data onto the root
filesystem. Unsafe/unsupported locations are rejected. A bounded fallback
spool requires advance administrator opt-in and protection. Location migration
must be integrity-checked, authorized and recoverable.

## Consequences

This design increases complexity in segment management, source acknowledgments,
quota accounting, mount identity, service permissions, replay, migrations and
benchmarking. It avoids binding large event archives to the operating-system
disk while preserving evidence provenance and privacy. Remote/network-backed
filesystems are outside the initial qualification scope.

## Related work

- [Storage placement contract](../STORAGE_PLACEMENT_CONTRACT.md)
- [Capacity model](../../development/RESOURCE_CAPACITY_MODEL.md)
- M6.3–M6.7, proposed M6.10/M8.10, M13.6, M14.1, M14.4, M14.6

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# ADR-0002 — Preserve Source Trust, Coverage and Original Evidence

**Status:** Accepted for M0.4 design; implementation unverified.
**Context:** Agentless IoT telemetry can have missing packets, spoofed
identifiers, unverified exports and incomplete network positions. A valid
certificate can authenticate an agent but not its claims.

## Decision

- Model identity of **transport principal**, claimed source, observation
  scope, asset attribution, and coverage as separate fields.
- Validate input and approved source/scope before normalization. Preserve
  original evidence where allowed, event/acquisition/receive times, and
  normalization provenance independently of alert/case comments.
- Classify sources by verifiable evidence; an unauthenticated syslog export
  never receives cryptographically authenticated status by implication.
- Unknown IoT devices in an approved passive scope can be inventoried and
  detected without agent enrollment. They gain no management privileges.
- Report missing telemetry and data loss as degraded coverage, not safety.
  IP, DHCP, MAC, OUI and firmware guesses may be uncertain. CVE confirmation
  requires appropriate corroborated model/version applicability data.

## Consequences and alternatives

Metadata and audit overhead are accepted for incident fidelity. Flattening
all sources into a trusted event stream, claiming 100% network visibility,
and fabricating model/firmware confidence are rejected.

**Revisit:** M5.10, M6.2/M6.5, M7.10, M9.2/M9.6, M10.9. Related
`TB-01`, `TB-02`, `TB-06`, `TB-07`, `TH-001`, `TH-002`, `TH-014`,
`TH-019`, `TH-029`.

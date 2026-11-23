<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0003 — Keep Observation, Egress and Response Authority Separate

**Status:** Accepted for M0.4 design; implementation unverified.
**Context:** KnetSentry must observe Internet-facing traffic involving
approved LAN devices, while legitimately syncing CVE/ATT&CK/KEV information.
These are different operations, and neither permits arbitrary probing or
uploading private logs.

## Decision

- `C-02` uses distinct policies for network observation, agent transport,
  approved public intelligence access, local administrative operations and
  incident response. A local observed Internet peer never becomes an approved
  outbound destination.
- Only `P-10` performs opt-in feed HTTPS, restricted to approved provider
  identities, origins, resolved/connected destinations, TLS policy, response
  sizes and validated content. Untrusted log fields cannot select arbitrary
  URLs; feeds cannot write policy or events directly.
- All active response is disabled by default and requires independently
  authorized, user-reviewed, scoped action via `C-16` and `P-12`.
- Host enforcement is separately installed/verified; application authorization
  does not substitute for effective firewall/sandbox checks.

## Consequences and alternatives

Extra policy and feed-worker complexity is accepted. A universal network
client accessible from detections, AI, or user-supplied event URLs is rejected.
Precise provider allowlist format, proxy strategy and DNS handling are
scheduled for M3.9; feed parsing and caching belong to M10.9.

**Revisit:** M3.1/M3.5/M3.9, M10.9, M11.5. Related `TB-08`, `TB-11`,
`TB-12`, `TH-012`, `TH-013`, `TH-020`, `TH-023`, `TH-027`, `TH-041`.

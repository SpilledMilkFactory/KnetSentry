<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0001 — Separate Security Domains by Operating-System Process

**Status:** Accepted for M0.4 design; implementation unverified.
**Context:** Agentless capture needs limited elevated capability; raw packets,
network logs, feeds, and optional AI are untrusted. A monolithic root manager
would unnecessarily combine these attack surfaces with privileged authority.

## Decision

- `P-01` manager remains unprivileged and owns authorized event state,
  scheduling and storage through typed C++ modules.
- `P-04` broker has only reviewed capture privileges and never interprets
  application protocol payloads; `P-05` sensor parses in a different,
  unprivileged and OS-confined process.
- `P-07` authenticated listener is independent of policy/DB administration.
- `P-10` public HTTPS feed worker is confined to approved providers; `P-11`
  offline AI has **no network egress**. Neither holds manager DB or response
  authority. `P-12` privileged policy applicator receives narrow, validated,
  explicitly authorized proposals; no event-to-policy fast path.
- Optional `P-08` agents and `P-09` helpers are independent of the manager.
  `P-02` Qt GUI and `P-03` CLI use authorized local IPC only.

## Consequences and alternatives

More process startup, local IPC and packaging complexity are accepted to
reduce blast radius. A single privileged daemon or embedded packet parsing
inside the capture broker is rejected for the v1.0 baseline. An eBPF-based
sensor may be evaluated in M5/M9 but must preserve the same trust and
privilege separation. systemd sandbox directives require deployment testing;
security cannot be assumed from configuration syntax alone.

**Revisit:** M2.7, M3.5, M5.10, M13.6. Related `TB-03`, `TB-05`, `TB-08`,
`TB-09`, `TB-11`, `TH-003`, `TH-010`, `TH-020`, `TH-024`.

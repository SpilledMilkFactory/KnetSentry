<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M3.2 — IPv4 and IPv6 network-scope validation

Issue #27 extends the `C-02` / `TB-11` M3.1 policy preflight, not the
manager's file configuration or an operational IP transport.

## Approval and evaluation contract

The three-argument `NetworkScopePolicy::compile(1, generation, endpoints)`
remains the exact-address interface. The explicit four-argument
`compile(2, generation, endpoints, prefixes)` accepts `PrefixApproval`
entries alongside exact `EndpointApproval` entries. Schema 2 does not change
the manager's configuration-file schema. Both inputs are trusted,
administrator-approved data; compilation copies normalized values into a
fixed-size snapshot. The combined maximum is 64, generation must be nonzero,
and an invalid entry rejects the entire snapshot. A valid empty policy denies
all operations. There is no implicit migration or wildcard approval.

A prefix uses a numeric CIDR network, e.g. `192.0.2.0/24`,
`2001:db8:abcd:1200::/57` or `fe80::/64`, with exact expected agent/manager
identity, nonzero interface index and nonzero TCP destination port. The
prefix does not authorize enrollment, discovery, observation or any other
purpose. Proposed endpoints and route evidence remain single numeric addresses,
not CIDR networks. All existing purpose, route kind, interface, generation and
exact route-destination checks remain in effect. The route must be on-link
unicast. Positive results remain `CandidateInScope`, never a connection permit.

## Address and prefix rules

- Require a canonical network base (all host bits zero); do not mask away
  accidentally supplied host bits. Accept compressed/expanded and case-equivalent
  IPv6 spellings with the same numeric value.
- Require a decimal length of 1–32 for IPv4 or 1–128 for IPv6, without
  signs, whitespace, leading zeros or other syntax. `/0` is denied in both
  families. Bound text before parsing. Reject NUL, embedded zones, hostnames,
  bracketed addresses, alternate IPv4 encodings and mixed dotted IPv6 literals.
- Compare only within the same family, including partial octets. IPv4-mapped,
  compatible and known transition IPv6 addresses remain denied. Prefixes must
  fit wholly in the supported address classes: IPv4 excludes 0/8, 127/8 and
  addresses from 224.0.0.0 through 255.255.255.255; IPv6 permits global unicast-format, ULA and link-local,
  excluding 2002::/16 and 2001::/32. Reject broad prefixes spanning excluded
  ranges, even if their base is individually acceptable.
- Conservatively reject the IPv4 approval's all-zero and all-one host parts
  for lengths <=30. /31 and /32 do not have that prefix-edge restriction;
  /127 and /128 use ordinary IPv6 membership. This is not a determination of
  real subnet network/broadcast addresses or point-to-point topology.
- Reject duplicates and overlapping ranges for the same agent, manager,
  interface and port, including exact addresses within approved prefixes.
  This avoids ambiguous rule precedence and bypass of prefix-edge exclusions.
  Different explicit bindings remain independent. Disjoint prefixes may coexist.
- Keep link-local interface scope separate from textual addresses. IPv4 and
  IPv6 never inherit permission from one another. Private or globally formatted
  numeric addresses are not automatically authorized.

## Verification and limits

`knetsentry_network_scope_policy` remains mandatory. The additional
`knetsentry_network_prefix_validation` runs in all seven presets. It checks
mixed policies, malformed inputs, overlap order, combined capacity, route and
identity constraints, boundary hosts and a bit-by-bit sweep across IPv4 /8–/32
and IPv6 /8–/128 using synthetic bases. Both sanitizer configurations include it.
Run `python3 scripts/verify_m32_network_prefix.py --build-dir
build/presets/linux-release` for configured verification. No live network
communication is performed by the policy or these tests.

Advances `KS-NET-008`, `KS-NET-009`, `KS-NET-010`, `KS-NET-013`, `KS-NET-014`,
`KS-NET-026`, `KS-NET-029`, `TH-012`, `TH-013` and `TV-09` within the existing
`C-02` / `TB-11` boundary. These are partial preflight checks, not end-to-end
network-security qualification. Prefix authorization is not subnet discovery.
Actual interface identity, namespace, route freshness, local/broadcast address
classification, authenticated peer identity, connection binding, revocation,
OS firewall enforcement and session revalidation require further implementation.
The manager, systemd confinement, AF_UNIX IPC and GUI are unchanged. Separate
passive monitoring scope and administrator-approved public intelligence egress
remain future policies; no new I/O, privileges or provider permissions are enabled.

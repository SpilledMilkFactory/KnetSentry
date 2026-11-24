<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M3.1 — Network scope policy engine

M3.1 historical contract; M3.2 adds an explicit schema-2 prefix interface in
[the M3.2 validation contract](NETWORK_SCOPE_VALIDATION_M32.md).

Issue #26, component `C-02`, trust boundary `TB-11`. This is the initial
application-layer decision contract, **not active network enforcement**.
The existing lifecycle-only manager configuration and AF_UNIX interfaces are
unchanged. No component currently performs IP networking. Future network
operations must consult this boundary and enforce all additional prerequisites
before performing I/O; a positive decision alone never authorizes a connection.

## Policy and proposal contract

`knetsentry::core::NetworkScopePolicy` is a Qt-independent C++23 value snapshot.
`compile(schema, generation, approvals)` accepts trusted administrator-approved
input only. Schema 1, nonzero generation, at most 64 exact endpoint approvals,
and valid bounded fields are required. Invalid or duplicate approvals reject the
entire snapshot; default constructed and invalid policies deny all. Empty valid
policies also deny all. The policy owns copied, normalized approval data. It
has no policy mutation API, network I/O, DNS, file access or logging side effects.
This is an in-memory typed schema, not a manager configuration file format.

The only positive M3.1 profile is an outbound Agent / AgentTransport / TCP
proposal matching an exact approved agent identifier, expected manager identifier,
numeric destination, nonzero interface index and nonzero destination port. A
separate trusted route evidence input must identify the same destination and
interface, the current policy generation, and on-link unicast reachability.
Policy comparisons use binary numeric addresses; IPv6 compressed/expanded and
case-equivalent literals match. Numeric address class alone never grants approval.
The local interface index is mandatory even for IPv6 link-local addresses.
Embedded zone strings, mapped/compatible IPv4-in-IPv6, loopback, unspecified,
multicast, limited broadcast, reserved high IPv4 ranges and known IPv6 transition
ranges are denied. IPv6 support is limited to global unicast-format, ULA and
link-local literals in this profile. Directed broadcast and other route-specific
address semantics must be rejected by the future trusted topology adapter.

Fixed-size identity fields allow ASCII alphanumerics, hyphen, underscore and dot,
up to 64 characters. These are expected identity labels, not certificates or
proof of identity. The compiled decision does not authenticate either peer.
`CandidateInScope` is intentionally not named `AllowConnection`: live route and
interface validation, binding the actual connected endpoint, authenticated
transport, revocation, and OS enforcement are still required. The route evidence
is a trusted input contract, not an implementation of route discovery or
freshness. A policy generation match alone cannot establish topology freshness.
Future callers must obtain current evidence from the trusted local topology
adapter, not remote requests, telemetry or AI output, and must handle policy
activation/rollback under the administrator authorization contract. Interface
index reuse, namespaces, routes changing after a decision and session revocation
remain unqualified. There is no current production network caller to integrate.

## Denial and separation

| Decision | Meaning |
| --- | --- |
| `DeniedPolicy` | Invalid or unavailable snapshot |
| `DeniedPurpose` | Unsupported component, purpose or protocol |
| `DeniedEndpoint` | Invalid endpoint/identity/interface/port |
| `DeniedRoute` | Missing, unsupported or mismatched route evidence |
| `DeniedApproval` | No exact approved tuple |
| `CandidateInScope` | Initial preflight match only; not operational authorization |

No broad private-range or default-route permission is provided. Routed LAN/VLAN,
CIDR policy, inbound sessions, return-traffic tracking, active discovery,
monitoring-source authorization, provider DNS/HTTPS and intelligence sync are
not yet implemented and cannot yield positive decisions here. Passive observation
of approved local traffic including Internet peers is a separate future data
source policy, not an outbound communication permission. Approved public CVE,
MITRE ATT&CK and other support functions remain a distinct planned opt-in policy;
this initial denial is not a permanent prohibition on legitimate support egress.
The M2.7 manager remains confined and no firewall rules are modified.

## Verification and traceability

`knetsentry_network_scope_policy` is mandatory in all seven build presets.
Tests exercise exact approved synthetic IPv4 and IPv6 tuples, normalization,
link-local interface binding, empty/invalid/oversized/duplicate policies,
owned snapshots, unmatched identities/ports/addresses, malformed literals,
unknown enum representations, unsupported purposes and route classes, and
mismatched generation/interface/destination. No live LAN or Internet endpoint
is contacted. `scripts/verify_m31_network_scope.py` checks source registration
and optionally runs the compiled test against a configured build.

Advances `KS-NET-008`, `009`, `010`, `013`, `014`, `026`, `029` and the
separation required by `KS-NET-003`, `004`, `016`, `020`, `022`, `039`.
Traceability: `C-02`, `TB-11`, `TH-012`, `TH-013`, `TH-030`, `TV-09`, `TV-23`.
These are partial application-layer fixtures, not complete `CTL-01`–`CTL-06`,
`INT-*`, `MON-*` or `OPS-*` qualifications. Administrator approval persistence,
audit integration, CIDR evaluation, trusted topology acquisition, enforcement,
TLS and ongoing revalidation remain future work. Do not mark those gates passed.

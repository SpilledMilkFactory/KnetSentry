<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M3.3 — Linux interface and route awareness

Issue #28 advances C-02 / TB-11, KS-NET-007–010, KS-NET-013–015,
TH-013 and TV-09. This is read-only topology preflight, not a transport,
firewall, capture source or complete enforcement gate.

## Interface

`LinuxTopology` is a single-thread-owned, noncopyable observation epoch.
Construct it in the relevant Linux network namespace after administrator
validation of the attachment binding. `check_changes()` returns `Current`,
`Invalidated` or `Unavailable`. `Current` means the observation socket is
available and no invalidation has been observed, not that any route is approved.
`evaluate(policy, proposal, expected_interface)` returns the observation state
and a `ScopeDecision`. The expected interface name and policy are trusted
administrator inputs. The supplied `proposal.route` is ignored; the adapter
first checks the pure policy profile, then performs fresh kernel queries before
returning any positive candidate. It never returns reusable route evidence.
The first valid policy generation is bound to the epoch; any subsequent
change invalidates it. Policy publishers must use unique monotonic generations.

The adapter subscribes to link, IPv4/IPv6 address, route, routing-rule, nexthop,
network-configuration and IPv6 interface-information notification groups. A
pending notification (including unknown or irrelevant events), loss/error,
namespace identity change, thread-owner mismatch or interrupted poll causes
sticky invalidation. It does not drain and silently rearm the epoch. A fresh
instance requires revalidation of approved interface bindings and policy by
its caller. There is no background worker; callers must check the epoch at
operation boundaries and integrate readiness into future event-loop/session
revocation mechanisms. Every evaluation performs fresh checks; no positive
result is cached. A final notification check occurs after all kernel queries.

## Initial supported topology

- Explicitly approved numeric endpoint/prefix, expected identities, TCP port,
  nonzero interface index and separately supplied exact interface name.
- Read-only `RTM_GETLINK` verification of an active Ethernet-like interface
  with UP/RUNNING/LOWER_UP and no loopback, point-to-point or dormant flags.
  Known virtual, stacked, master/subordinate and cross-namespace attachments
  are rejected. The absence of those attributes is not proof of physical
  attachment or hardware identity.
- A fresh `RTM_GETROUTE` effective destination lookup and `RTM_F_FIB_MATCH`
  lookup in the current namespace. Both must report the approved output
  interface, main routing table and matching family, destination/prefix and
  unicast route. IPv4 FIB scope must be link-local; IPv6 may use universe scope.
  IPv6 link-local lookups use the explicit zone; other lookups do not force OIF.
- A nonzero canonical FIB prefix is required. A direct default route without a
  gateway is denied. IPv4 network/broadcast edges of the matched FIB prefix
  (length <=30) are also denied. Reject gateway, multipath, nexthop object,
  encapsulation, source-specific, unknown route attributes and unsupported
  route flags/types. Known non-path metadata is ignored after envelope checks.
  Effective IPv6 lookups without a requested source may report an unspecified
  source echo on kernels built with `CONFIG_IPV6_SUBTREES`. Only a single
  unflagged 16-byte all-zero `RTA_SRC` with source length 128 is recognized,
  and only for effective IPv6 replies. The source-free form is also supported.
  FIB replies must remain source-free; actual source-specific routes, nonzero
  sources, malformed or duplicate echoes, and all other unsupported evidence
  remain denied. All other route and attachment checks still apply.
- Bounded single-reply netlink queries, kernel sender check, exact sequence
  correlation, truncation/error rejection, and 250 ms poll per request (up to
  three requests per eligible evaluation). No socket in AF_INET/AF_INET6, DNS,
  probes, packet capture, shell command or configuration mutation in core.
  Any failed or unsupported inspection returns no positive candidate.

## Qualification

`knetsentry_network_topology_awareness` is mandatory in every preset. It uses
synthetic binary link/route fixtures, malformed/unknown attributes, IPv4/IPv6
boundary cases, notification readiness/error fixtures, live kernel loopback
link/effective/FIB replies, real subscription readiness, forged caller route
rejection and sticky policy-generation invalidation. It sends no IP traffic
and does not print local topology. Run `python3 scripts/verify_m33_network_topology.py
--build-dir build/presets/linux-release` for configured evidence.

An additional explicitly requested isolated test is available:

```bash
python3 -B scripts/check_m33_topology_namespace.py \
    --binary build/presets/linux-release/tests/knetsentry_network_topology_test
```

Run as the ordinary development user, not sudo. It requires iproute2, unshare,
allowed unprivileged user/network namespaces, IPv6 and veth support. It creates
a fresh single-UID user and network namespace and verifies its initial
loopback-only inventory before modifying it. It exercises real link, dual-stack
address, route and routing-rule notifications, direct route inspection,
gateway-free default-route rejection and veth attachment rejection. Synthetic
interfaces and routes are confined to the disposable namespace. No packets are
intentionally sent by the test, and no host route/interface or firewall is
modified. A blocked namespace test is not a passing live-change qualification.
The optional launcher reports three distinct outcomes:

- Exit 0 (`PASS`): the isolated child entered and completed all fixtures.
- Exit 77 (`BLOCKED`): a required launcher tool is missing or a recognized
  namespace setup permission denial occurred before any child output.
- Exit 1 (`FAIL`): all other failures, including actual fixture failures,
  unexpected launcher errors, missing/invalid compiled binary, missing
  completion evidence, and timeouts.

The launcher uses a fixed C locale to recognize specific `unshare` setup
errors (including `/proc/self/uid_map` permission denial). An error from an
entered child is never classified as blocked. Do not disable AppArmor, change
host namespace restrictions, or use sudo to bypass the optional test.
The source verifier exercises outcome classification without namespace changes.
The local acceptance runner can request it with `--topology-namespace`;
if blocked it reports a distinct BLOCKED count and partial acceptance (exit
77 unless another check fails). Omitting that option runs the standard
mandatory suite; it does not qualify live topology mutation on that host.
Run the optional fixture on a separate approved host or disposable VM where
unprivileged namespaces are permitted.

## Remaining constraints

No live networking caller exists. M3.1/M3.2 pure evaluation is still available
for fixtures; future operational callers must use the trusted adapter and all
additional gates. `CandidateInScope` is not a connection permit. The adapter
does not bind a real connected socket, prove source-address validity, MAC or
physical identity, detect all firewall or namespace changes between checks,
resolve routing-rule semantics for arbitrary socket marks/source ports/UIDs,
or close existing sessions. There remains a check/use race: even a final quiet
notification check is not an atomic kernel enforcement guarantee. The initial
profile rejects VLANs, bridges, bonds, tunnels and virtual links pending
reviewed topology support, and does not qualify routed LAN deployments.
A live positive physical-link deployment is not exercised by the isolated
fixtures. Independent enforcement, authentication, endpoint binding,
administrative approval persistence and actual session revocation are future
work. The manager, AF_UNIX IPC, desktop and hardened systemd service remain
unchanged; do not relax the service's existing netlink/IP isolation.

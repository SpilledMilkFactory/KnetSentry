<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M3.7 — Adversarial network-boundary qualification

Issue #32 extends the M3.6 disposable network fixture. It does not add
production networking or relax the M3.5 dedicated-manager deny-only profile.
Traceability: TB-11, TH-013, TV-09, KS-NET-008/009/013–015/028–030.

## Mandatory offline evidence

`knetsentry_network_adversarial_boundary` invokes the existing compiled
isolation test with `--adversarial` in every preset, including sanitizers.
It checks IPv4-only and IPv6-only prefix policies, cross-family isolation,
outside-subnet rejection, ambiguous IPv6 forms (mapped, transition,
multicast, unspecified, loopback and embedded zone), component, purpose,
protocol, agent, manager, port and interface substitution, and inconsistent
route destination, interface, revision and route classifications. Positive
controls are preflight candidates only, never operational permits.
`python3 -B scripts/verify_m37_adversarial.py` checks the fixed fixture
inventory, TCP-only firewall structure, UDP outcome classification and
credential arguments, and rejection of arbitrary topology mutations.

## Explicit live evidence

Use the existing M3.6 administrator-only command after reviewing the source:

```sh
sudo /usr/bin/python3 -I -B scripts/network_fixture_m36.py \
  --binary build/presets/linux-release/tests/knetsentry_network_isolation_test
```

The two unnamed namespaces still have no external attachment or default
route. Additional documentation-range addresses on the same veth segment
(`203.0.113.1/24`, `203.0.113.2/24`, `2001:db8:38::1/64`,
`2001:db8:38::2/64`) make unapproved subnets reachable without a gateway.
The original eight TCP cases are retained. Two additional TCP endpoints and
four UDP endpoints (approved TCP destinations and additional subnets, same
numeric port) must echo the fixed token before filtering. The unchanged
M3.6 TCP-only test rules must then deny the extra TCP and all four UDP probes
from the dedicated UID. Each denied probe requires drop-counter advancement
and a successful control-UID exchange. All paths must work after table
rollback. A UDP send permission error (local-output drop) or receive timeout
after successful connect and send is a denial candidate only; the drop counter
and control-UID exchange are still required. Other probe errors fail.

The harness next synchronizes a fresh authorization watcher with each fixed
IPv4 and IPv6 host blackhole route insertion and the synthetic link-down
operation. For blackhole routes, effective and FIB lookups must both reject
and return to the existing accepted route representation after deletion.
The same watcher must remain invalidated after restoration (route deletion
or link-up), deny subsequent requests and reject reactivation of its consumed
revision. Link-up is a transition test, not a claim of restored IPv6 address
configuration or connectivity. Route mutations and link transitions are
restricted to the disposable sender namespace. Existing peer reaping and
namespace disposal remain mandatory. No repository-built executable runs as host root; the compiled fixture runs
with ordinary caller credentials in the delivered harness.

## Acceptance and limitations

All ordinary checks and explicit live M3.5/M3.6/M3.7 qualification must pass.
An explicit live-test failure is not a skip. The source-only verifier and
compiled matrix do not demonstrate actual kernel filtering. The fixture
requires the existing Python, iproute2, nftables, veth, IPv6 and dedicated
UID prerequisites. No host firewall change or security-control relaxation
is needed. The fixture does not qualify real physical attachment, agent
identity authentication, production transport, proxy or privileged attacker
resistance, persistent enforcement or active monitoring. The test-only
positive permissions are not production permissions.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M3.6 — Network isolation and policy test fixtures

Issue #31; TB-11, TH-013, TV-09; verification coverage for KS-NET-008,
KS-NET-009, KS-NET-013–015, KS-NET-028–030. No normative permission is changed.

## Separate evidence levels

The mandatory `knetsentry_network_isolation_fixture` CTest case exercises the
existing compiled scope policy using fixed documentation-range endpoints. It
requires no root, nftables, external DNS, Internet access, or IP packet delivery.
The source verifier `python3 -B scripts/verify_m36_network_fixture.py` checks
fixture generation, namespace-entry guards, default-route rejection, credential
arguments, and probe-result classification. Neither qualifies live enforcement.

The explicit live regression creates two disposable Linux network namespaces
and a single veth pair entirely inside them. No named namespace mounts, host
interfaces, host routes, host firewall tables, default routes, forwarding setup,
or Internet access are needed. The parent checks both namespace identities and
initial loopback-only inventories before creating or moving the synthetic link.
The peer binds only the fixed test addresses after dropping credentials.

| Fixture | Sender address | Peer addresses |
| --- | --- | --- |
| IPv4 | 192.0.2.1/24 | 192.0.2.2, 192.0.2.3 |
| IPv6 | 2001:db8:36::1/64 | 2001:db8:36::2, 2001:db8:36::3 |

All four peer addresses listen on TCP ports 37443 and 37444. The eight baseline
probes require a successful fixed four-byte echo. The test-only nftables table
allows the dedicated service socket UID only to the two `.2` / `::2` peers on
TCP 37443 through `ks36a`; the final UID-specific rule drops other IP traffic.
Six reachable but unapproved address/port combinations must fail at connect
while the corresponding drop counter increases. Both approved paths must echo
and their respective allow counters must increase. The separate control UID must
still echo on all eight paths. After table-only rollback all eight service UID
paths must echo again. This fixture rule is not a production firewall template.
The M3.5 deny-only production profile remains unchanged.

The compiled live test runs as the ordinary sudo caller, not root. It verifies
actual effective/FIB routes, denies out-of-segment route evidence, and exercises
production virtual-interface denial and stale-generation rejection. A separate
watcher runs under the same ordinary identity and must withdraw authority after
an actual synthetic link-down notification. The existing C++ production gate
must deny even where the test-only firewall permits packet delivery. The fixture
never treats synthetic TCP echo as authenticated agent transport.

## Run on the target workstation

Prerequisites: Ubuntu 26.04, Python 3.13+ with `os.unshare`, iproute2, nftables,
IPv6 and veth support, the M2.7 dedicated service account, the distinct `nobody`
account, permitted administrator network namespace creation, and a completed
Release test build. Review the repository test script before explicit elevation.
Run from the repository root as the ordinary developer:

```bash
ctest --preset linux-release -R '^knetsentry_network_isolation_fixture$' --verbose --no-tests=error
sudo /usr/bin/python3 -I -B scripts/network_fixture_m36.py \
    --binary build/presets/linux-release/tests/knetsentry_network_isolation_test
```

The developer's local runner may request this with `--network-fixture` alongside
`--systemd` and the existing `--firewall-namespace`. Do not run the entire runner
as root. The test requires a normal sudo caller with a nonzero UID and its
primary GID. It performs fixed synthetic operations only, with bounded command,
connection, readiness, idle, and shutdown deadlines. If a phase fails, the parent
closes the control channel and kills/reaps its peer if necessary; the unnamed
network namespaces disappear when their last references close. No host firewall
installation or cleanup command is required. Do not weaken AppArmor or namespace
restrictions if a prerequisite is denied. Use an approved disposable target VM
if necessary. Any unsuccessful explicitly requested test is a failure, not a pass.

Successful completion requires `M3.6 isolated network fixture: COMPLETED` and
exit status zero. Source/CI verification cannot substitute for that result.
The fixture does not test UDP positive permissions, physical interface approval,
mutual TLS, operational session revocation, or deployed firewall persistence.
It is a TCP test fixture for the initial agent preflight profile only. No packet
capture, device discovery, host LAN access or public intelligence access is added.

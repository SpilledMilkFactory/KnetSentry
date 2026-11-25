<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M3.5 — Lifecycle-only operating-system firewall profile

Issue #30; advances TB-11, TH-013, TV-09 and KS-NET-014/015/028/029/030.
This is the initial deny-only profile, not a complete operational transport
firewall or a claim of deployed enforcement. The M2.7 installed manager is
still AF_UNIX-only, has a private network namespace and no capabilities.
No application or systemd setting changes. The desktop-owned manager runs
as the desktop user and is intentionally not subject to this UID rule.

## Threat model and rules

The administrator controls a dedicated non-login `knetsentry` account, kernel,
network namespaces and host firewall. Do not share or recycle the service UID
while its rule exists. The renderer resolves the installed account (never a
caller-provided UID), checks its nonzero identity and expected sysusers group,
home and shell, and produces a fixed three-command nftables transaction.
An `inet` output filter matches socket UID and drops IPv4/IPv6 packets for that
UID, including loopback, TCP and UDP; an anonymous counter records totals only.
There are no accept exceptions, connection-state exceptions, IP/port grants,
DNS requests or provider permissions. The base chain's accept policy leaves
nonmatching traffic to other firewall chains; it cannot override another
chain's drop. No inbound or forwarding rule changes are made.

This is defense in depth for sockets attributed to that UID in the namespace
where the table is installed. The installed manager's existing private network
namespace and AF_UNIX-only restriction are still essential. A host-namespace
nft table does not propagate into another network namespace; socket UID is not
process identity, a complete IPC/proxy restriction, or a defense against root,
CAP_NET_ADMIN, socket passing, or a compromised kernel. No raw/packet sockets,
forwarded traffic or unowned kernel packets are qualified by this rule. Future
network-enabled agents/manager components need dedicated identities, reviewed
per-direction scoped rules, trusted policy publication, kernel enforcement
revalidation, socket binding and session revocation before enabling transport.

## Verification (no host changes)

`python3 -B scripts/verify_m35_firewall.py` exercises deterministic generation,
invalid UID, account checks, strict JSON read-back and namespace-entry failure.
CTest and CI run these unprivileged fixtures; they do not prove nft syntax or
kernel effectiveness. For actual qualification, install the OS packages
`nftables` and `iproute2` if absent (review existing firewall ownership first;
do not enable/restart the nftables service just for this test). The M2.7 sysusers
account must already exist. Review the script before elevating it, then run:

```bash
sudo /usr/bin/python3 -I -B scripts/firewall_m35.py live-isolated
```

This separate process enters a new network namespace before any mutations,
requires a loopback-only inventory and empty firewall, and uses only loopback
TCP/UDP in both address families. It verifies baseline delivery, nft check and
atomic creation, strict actual JSON read-back, collision rejection, failed
batch preservation, UID-specific denial with advancing counters, unrelated UID
delivery, unrelated-table preservation, and rollback/restored delivery.
No interface or firewall changes propagate into the caller's namespace. No
public/LAN packets are sent. The process and its subprocesses release the
namespace at exit. Missing prerequisites, namespace denial and genuine failures
are nonzero; no successful qualification is claimed unless all fixtures finish.
The root test is explicit and separate from public PR jobs. Do not disable
AppArmor or other protections to run it. Use an approved disposable Ubuntu VM
if the workstation cannot create a privileged namespace.

## Optional explicit host deployment

This is not an automatic installer, systemd dependency, or boot-persistent
firewall service. The manager remains IP-disabled whether the table exists or
not. Coordinate with the host firewall administrator, review the source and
ensure the dedicated UID is not used by other services. Stop the installed
manager before installation/removal; leave desktop development unaffected.
Never flush the host ruleset or reload a firewall manager just for this profile.
The name `inet knetsentry_m35` is reserved for this exact profile: if it already
exists, inspect it, do not replace or delete an unknown table. Perform operations
serially with other privileged firewall administrators and configuration managers.

```bash
sudo systemctl stop knetsentry-manager.service
umask 077
rules=$(mktemp)
python3 -B scripts/firewall_m35.py render > "$rules" && cat "$rules"
```

Only proceed after a successful render and review (exactly the three commands
above, with the actual dedicated UID). The administrator must ensure that the
file cannot change between review and application. For example copy it to a
root-owned private directory under `/run` and review that copy before loading.
Do not load user-supplied or remote rule files as root.

```bash
sudo install -d -o root -g root -m 0700 /run/knetsentry-firewall-m35 &&
    sudo install -o root -g root -m 0600 "$rules" /run/knetsentry-firewall-m35/profile.nft &&
    sudo cat /run/knetsentry-firewall-m35/profile.nft
```

After reviewing the root-owned copy, run separately:

```bash
set -o pipefail
sudo nft -c -f /run/knetsentry-firewall-m35/profile.nft &&
    sudo nft -f /run/knetsentry-firewall-m35/profile.nft &&
    sudo nft -j -n list table inet knetsentry_m35 | python3 -B scripts/firewall_m35.py verify-json
```

Stop on any failure. `create table` is exclusive; a conflict cannot silently
append or replace rules. The file is applied as one nftables transaction. The
read-back verifier requires exactly the expected table, output chain, socket UID
match, counter and drop; missing, duplicate, extra, changed or unknown objects
fail. It validates the returned structure, not continued enforcement or actual
host traffic. If a firewall manager reloads rules, or the UID changes, revalidate;
absence, failed read-back or changed policy cannot be treated as permission to
start any future IP transport. Automatic persistence, reconciliation and
continuous enforcement monitoring are not implemented. Do not restart the
manager until the administrator has addressed any unexpected outcome.

Rollback only if the read-back succeeds and the administrator confirms table
ownership, the manager is stopped and no other privileged writer is changing
it. Removing the table intentionally removes this additional defense; the
unchanged M2.7 confinement still prohibits IP transport.

```bash
set -o pipefail
sudo nft -j -n list table inet knetsentry_m35 | python3 -B scripts/firewall_m35.py verify-json &&
    sudo nft delete table inet knetsentry_m35 &&
    sudo rm -f /run/knetsentry-firewall-m35/profile.nft
rm -f -- "$rules"
```

The read-back/delete sequence is not race-free against privileged writers;
serialize administration. Do not remove an unknown/conflicting table. Keep the
service stopped until deployment or rollback is resolved. No change to existing
nftables configuration files or unrelated tables is required. A reboot may
remove the manually installed table; do not infer persistence. No public
intelligence or agent traffic is authorized by this milestone.

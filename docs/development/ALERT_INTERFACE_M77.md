<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M7.7 — Alerts interface

Issue #66: explicit development-only, same-user foreground manager integration
for existing M7.6 persistent alerts. No background scheduling or detection,
production analyst roles, service-account access, remote listeners or response
capability. The default installed manager and normal desktop startup expose no
alert records. Existing STATUS/HEALTH/AGENTS/EVENTS and ADMIN denial are preserved.

## Activation and authority

`knetsentryd --ipc-dir ABS --audit-dir ABS --event-store-dir ABS --alert-dir ABS
--alert-access read|ack` requires all alert options,
a separate approved existing private SQLite store and alert ledger, persistent
private audit, and the existing authenticated same UID/GID Unix socket. `ack`
is explicit write opt-in; `read` refuses acknowledgement. The manager derives
actor `uid-N` from SO_PEERCRED and obtains its own wall-clock timestamp. The
client cannot choose identity, time, directory, policy or new lifecycle state.
The manager audits authorization before accessing the ledger and successful
acknowledgement before returning success. An interrupted response or audit failure
after commitment is uncertain; refresh to inspect persisted status, never retry
blindly. Same UID/GID is a development trust boundary, not per-application or
production analyst RBAC. All processes with that identity can use opted-in IPC.
Read-only inspection refuses pending transactions without removing them. The operator must approve stable directory/mount and store identities and keep
other writers quiescent. No production or systemd unit configuration change.

The single supported profile is exact `ssh.service`, `ssh-failure` v1,
Authentication / Logon / Failure, Medium, two matching events, window 60000 ms,
interval 1 ms, suppression 0, title `Authentication failures`, description
`Two scoped SSH failures.`; schema and mapping use the pinned native versions.
The private 0600 single-link `alert-scope-m77.v1` file in the approved alert directory contains exactly `STOREID:BINDING` followed by LF. No scope identity is passed in argv. `STOREID` is 64 lowercase hexadecimal digits, `BINDING` is 96. Both must match the
ledger's policy commitment. This intentionally limited development profile is
not an arbitrary-rule loader or a production alert catalog. It does not migrate,
initialize or reinterpret existing ledgers with different rule metadata.

## Protocol and GUI

`KSIPC/1 ALERTS` uses the existing 4-byte bounded local framing. Requests have
an operation (L=list, A=acknowledge, E=linked evidence), severity selector
(0=all, 1..6=rule severity + 1), offset, generation, trigger, revision, evidence
ID and manager session. All irrelevant fields must be zero/default. Exact
canonical encoding and reply correlation are required. List pages contain at
most eight summaries and are ordered by generation/trigger. Offset continuation
is valid only for the same manager session; this is not a globally atomic
snapshot across pages. Ledger is append-only for alert identities; refresh for
current lifecycle revisions. Acknowledgement requires current stable key,
revision, session and write permission. No resolve, delete or note mutation is
exposed. Evidence inspection checks membership in the selected alert and reads
raw/normalized storage only in the manager, compares binding, exact unit,
collector, timestamps, digest and integrity origin. A historical reference with
missing or changed evidence is unavailable, not silently substituted. The GUI
receives minimized normalized details, no raw messages, notes, binding or digest.

Qt uses a bounded list model and virtualized ListView with severity filter,
explicit refresh, continuation, detail panel, acknowledgement button and exact
linked-evidence inspection in the Alerts page. No direct file or SQLite access
from QML. Replies expire after 30 seconds and selection clears on navigation.
Acknowledgement clears the page and requires refresh to inspect committed state.
Alert severity describes rule priority; acknowledgement is not remediation.

## Verification

`knetsentry_alert_interface_contract`, `knetsentry_alert_interface_runtime`,
`knetsentry_gui_alert_interface_runtime` (non-sanitized desktop only) exercise
synthetic persisted evidence and scheduler-generated alerts, bounds, filtering,
exact links, stale session/revision refusal, default denial, read-only refusal,
acknowledgement, audit, original evidence invariance, restart and rendered GUI.
Fixture seed accepts only new empty private directories; never seed production.
Target host qualification passed; manual GUI review and merge reported successful. Remaining #66 scope: general multi-rule and
multi-endpoint administration, independent analyst identity/roles, production
manager integration, full event explorer cross-page navigation and operational
alert creation. Existing #63/#64/#65 scope remains outstanding.

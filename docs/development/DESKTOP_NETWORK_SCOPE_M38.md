<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M3.8 — Desktop LAN scope inspection

Issue #33 adds a read-only **LAN Scope & Network Authorization** section to
Settings (Ctrl+7). The seven primary destinations, global daemon controls,
monitoring-unavailable notice and existing lifecycle behavior are retained.
Traceability: TB-05, TB-11, I-01, TH-010, TH-013, KS-NET-026–030.

## Evidence and authority

The current manager accepts only lifecycle-only v1 configuration. The M3.1–M3.4
policy and topology components are implemented and tested, but no operational
policy is activated or published by the manager. M3.8 does not add a policy
publisher, policy editor, discovery, positive transport authorization or a
firewall management operation. It cannot populate actual approved networks,
interfaces, policy revisions or network-denial records until those data are
available through an explicitly authorized management interface.

The existing read-only C++ `ServiceHealthModel` exposes four additional
non-writable Qt properties to the Kirigami Settings page. It derives
lifecycle-only presentation from the current verified KSIPC/1 HEALTH contract;
this is not a separate policy query or an independent firewall attestation.
No additional request, timer, IPC operation or daemon privilege is added.

| Card | Current verified health | No current verified health |
| --- | --- | --- |
| Policy state | Lifecycle-only contract, authorization not activated; default or validated v1 config | Unavailable |
| Approved networks and endpoints | No operational approvals loaded; inventory not published | Inventory not reported |
| Approved interfaces | No operational bindings loaded; local adapters are not approvals | Inventory not reported |
| Denied-connection diagnostics | Network denial count unavailable; actual local IPC rejection count separately labelled | Both counts unavailable |

The existing health client clears snapshots on refresh, failed or invalid
exchange, and endpoint reset. The view uses that same availability gate and
updates on the existing model signal. Owned-daemon Stop clears the endpoint;
external manager loss is observed on the next health poll (30-second interval,
plus the existing bounded two-second exchange). The page does not cache old
values as current. It does not treat a successful health exchange as proof of
monitoring, active enforcement, a safe network, or an absence of attacks.
A zero local IPC rejection count is not a zero network denial count.

The static policy-requirements card explains the initial agent transport
boundary and the separation of monitoring and intelligence authorization.
It is labelled as requirements, not actual approvals. Neither actual LAN
addresses nor test-fixture addresses are displayed or recorded by this page.

## Verification

Run `python3 -B scripts/verify_m38_desktop_scope.py` for the source contract.
With `--build-dir build/presets/linux-release`, it also runs the existing
Qt health-model and primary-navigation regressions. The existing Qt Test
executable checks non-writable metadata and attempted property writes. The
owned-manager lifecycle test checks the model across start/stop cycles.
Primary navigation checks Settings-only visibility and unavailable card text
in every desktop configuration, including the existing sanitizer run.

The existing `knetsentry_gui_health_runtime` test now starts a real private
manager with safe defaults, generates one fixed denied local administrative
request, checks the Dashboard and Settings, stops the manager, and verifies
that all current scope information clears on the same Settings page. It then
restarts the manager with a private validated v1 configuration, verifies the
new snapshot (local IPC counter zero, network denial count still unavailable),
and returns to the Dashboard. The test does not use a production allowlist or
transmit IP traffic. No existing sanitizer exclusions or suppressions change.

Manual: launch the desktop, open Settings, inspect the four cards while stopped,
start the owned manager, verify lifecycle-only state and no operational approvals,
stop it while remaining on Settings and verify current data becomes unavailable.
Restart, navigate away/back, resize to the minimum window size and scroll to all
cards, and close the window with an owned manager running. For an external
same-UID/GID manager, the existing read-only IPC behavior and disabled lifecycle
controls remain unchanged. Re-run the full existing acceptance matrix including
M3.5/M3.6/M3.7 live security checks and all nine hosted checks.

This issue does not qualify a positive policy publication API, administrator
role elevation, configuration writes, a deployed firewall state query, actual
network denial events, active monitoring, or public intelligence egress.
Future operational policy publication must revisit the explicit lifecycle-only
presentation and its source guard rather than infer policy from health.

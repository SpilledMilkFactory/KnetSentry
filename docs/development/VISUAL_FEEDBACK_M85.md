<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M8.5 — Application animations and visual feedback

Issue #73. Implemented foundation qualified and merged; broader operational performance and accessibility scope remains outstanding. Presentation-only motion,
loading feedback and non-modal status notifications. The default is reduced
motion; the toolbar checkbox allows session-only opt-in. The preference is not
persisted and does not modify the M8.3 layout schema. Startup remains windowed
1920 × 1080 logical pixels.

## Motion policy

The Kirigami platform short-duration hint is consulted continuously. A value
of one millisecond or less disables first-party decorative motion even when
the user opts in. Otherwise the navigation accent uses the lesser of the hint
and 120 ms. A single title underline fades after successful top-level page
replacement. The underline never contains data and is not a transition of
page content. Repeated navigation restarts the same animation. Turning reduced
motion on cancels the accent and hides it immediately. Minimized or hidden
windows do not run the added animations. A static focus/hover accent remains
usable independently of motion.

The existing health pulse drawing is suppressed in reduced-motion mode; the
health color and actual status text remain immediate. This is a successful
local health exchange, not monitoring activity. No alert severity, evidence,
chart count, availability badge or monitoring coverage state is animated.

## Operation feedback and notification

The footer displays the actual daemon control status, not a synthetic success
or alarm. One pending indicator is bound to the currently active Dashboard,
Events, Alerts or Investigations model's busy property. Its text and static
marker are available without motion. If motion is permitted, the marker rotates
once per 900 ms while the real request is pending; it stops on completion,
clearing, navigation away, reduced motion or window minimization. Existing
model result/refusal messages and workspace save status remain immediate. No
notification queue, modal dialog, synthetic timer or desktop notification
service is introduced. No extra evidence queries, persistence, network access,
privileges or authorization changes. Framework-owned control, drawer and window
manager effects remain subject to the platform and are not overridden globally.
The platform hint is not a universal cross-desktop reduced-motion API.

## Qualification

The existing visual-system test exercises default reduced motion, opt-in,
platform duration bounds, 16 immediate navigation replacements and cancellation.
The rendered Dashboard fixture asserts pending text in reduced motion, opt-in
and cancellation during the same real authorized and denied request, completion
clearing, and retains exact query counts and evidence invariance. These tests do
not require real LAN data. Run `ctest --preset linux-release -R
'^knetsentry_(visual_system|gui_dashboard_runtime)$' --verbose --no-tests=error`
(one command). Check the new footer state, toggle, focus/hover accent and
navigation feedback manually. Test KDE animation speed set to Instant and
restore its original value afterwards. Verify pending text and immediate
result/expiry/navigation clearing in both motion modes, minimize/restore, and
repeat rapid navigation. All seven presets, strict QML, manual visual checks
and hosted CI remain required. Production-scale performance and comprehensive
cross-desktop accessibility qualification are not established by these tests.

### Maintainer qualification

Reported 161 consolidated gates, 584 configured CTests, 76 structural
verifiers, 40 repeated rendered integrations, 200 repeated Release and 100
repeated sanitized executions, strict QML and diagnostic review, nine hosted
checks and successful manual qualification. See [project status](../PROJECT_STATUS.md).

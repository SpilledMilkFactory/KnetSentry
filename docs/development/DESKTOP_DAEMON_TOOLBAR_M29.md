<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M2.9 — Global daemon toolbar and lifecycle controls

The primary window header contains the drawer toggle, active page title, and a
persistent daemon status dot, activity line and play/stop controls. The colors
use the platform's negative, neutral and positive semantic text colors. Hover
text and accessible names explain the meaning independently of color.
A successful validated HEALTH exchange produces a short (900 ms) waveform;
otherwise the line is flat. The line uses fixed Qt Quick rectangle geometry
instead of a raster-backed Canvas, avoiding a paint surface for this small graphic. This is an observation of the desktop's own health
exchanges, not continuous daemon activity, a CPU graph or monitoring coverage.
Normal polling remains 30 seconds. Initial readiness of an owned child is
checked at most every 250 ms for five seconds, with at most one exchange active.

## Ownership and authorization

Launch the build-tree desktop normally, without `--ipc-dir`, and press Play.
The C++ controller uses the fixed build-tree sibling `../manager/knetsentryd`
(relative to the desktop executable, never PATH or a shell) and a new private
`/tmp/ks29-XXXXXX` directory per invocation. No endpoint is auto-discovered.
The process is a same-user foreground development manager using the existing
safe defaults and optional-audit policy (no persistent audit requested by this
mode). Its diagnostics are forwarded to the launching terminal. Stop signals
only the QProcess-owned child; a clean exit returns to the stopped state and a
new Play starts a fresh session. Failed transitions are visible; an unresponsive
child can be asked to stop again. On normal desktop exit, the controller requests
termination and waits up to three seconds before a child-only forced termination
fallback (followed by a bounded wait). When closing during startup it first waits
for process creation and briefly for socket readiness so the manager can install
its shutdown signal mask. Normal GUI exit explicitly checks the result; the
controller destructor repeats the idempotent cleanup if necessary. Only empty
private directories are removed, never recursively. A stale socket or unexpected
file is preserved; an incomplete close reports failure rather than claiming clean
shutdown. The fallback can leave an incomplete service session. Abnormal desktop
termination can leave a child running; this is not a production supervisor. No privileged service
installation, systemctl, sudo, PID discovery, or arbitrary command execution is
provided. Root desktop controls are disabled. Production installation paths
and a separately authorized systemd control interface are future work.

With `--ipc-dir`, the existing M2.6 observation mode remains read-only and both
lifecycle buttons are disabled, even when the external endpoint is unavailable.
The dedicated M2.7 service remains administrator-controlled; its mandatory audit
and confinement policies are unchanged. The desktop does not control it. This
advances the desktop presentation (C-03/C-20, I-01, TB-05, KS-NET-012, TH-010,
TH-011) without closing broader authorization threats. Same-UID impersonation
remains a limitation of the existing IPC trust model.

## Verification

`knetsentry_qt_daemon_control` exercises the controller in applicable desktop
builds, including sanitizers. `knetsentry_gui_daemon_toolbar` exercises the
actual embedded QML button signal bindings, state, restart, navigation and
window close with an active owned manager in non-sanitized builds. The controller
test verifies destructor cleanup of a running child (reaped PID and removed
private endpoint), immediate startup shutdown, idempotence, and preservation of
unexpected fixture data. Existing sanitized QML startup/navigation coverage and
third-party leak suppression scope remain unchanged. Run the normal acceptance
runner and manually inspect the global header on all seven destinations, at
minimum window size, with the daemon running and stopped. Confirm the tooltip,
icons and pulse (on start and each successful health refresh). Check external
observation separately if desired. No real network traffic is needed.

Keep temporary source archives outside the repository when running official REUSE
lint. The untracked archive is not source and must not be given a fabricated
license or excluded by a blanket archive rule. QML static analysis is gated on
first-party warning-free output; the existing navigation test and scoped LSan
policy remain enabled.

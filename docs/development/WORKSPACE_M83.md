<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M8.3 — Configurable multi-panel workspace

Issue #71. Candidate pending Ubuntu 26.04 qualification. This is presentation-only
workspace customization, not a monitoring or evidence authorization mechanism.

## Interaction

The desktop requests a 1920 × 1080 logical-pixel client area on each launch,
in ordinary windowed mode (not maximized or fullscreen). The existing 700 × 480
minimum and manual window resizing remain. The compositor/window manager may
constrain the actual dimensions on smaller or scaled displays; decorations are
additional. Window geometry is not part of saved workspace preferences.

The Dashboard always retains its SOC overview, security limitations, refresh control
and global manager status. In wide mode (content width at least 1000 logical pixels)
with charts enabled, the SOC overview and stored charts are adjacent panels. A
keyboard-operable width control adjusts the overview's requested share from 30 to
70 percent in five-point steps. The layout stacks on narrower displays; the
preference is retained when widening again. Detailed health and local telemetry
remain separate, optional Dashboard sections. Asset-page telemetry is unaffected.

Balanced/reset (50%, all sections), Evidence focus (40%, charts only), and
Operations focus (60%, health and telemetry only) are predefined starting points.
Section checkboxes and width changes are applied to the current layout immediately.
Save workspace layout explicitly persists the current selection. Reset is not
persisted until Save is pressed. No arbitrary docking, custom panel ordering,
multiple named saved workspaces or window geometry persistence is implemented.

## Persistence and trust boundary

Only a ten-byte fixed schema is persisted: `KSW1:50:7` plus LF. The width is one
of 30, 35, 40, 45, 50, 55, 60, 65, 70. The visibility mask uses charts=1,
detailed health=2, local telemetry=4; 0–7 are valid. No evidence snapshots,
credentials, filters, queries, paths, manager endpoint, operational settings or
privileges are serialized. The startup page remains Dashboard.

The per-user generic configuration root (normally `~/.config` or the explicitly
set XDG_CONFIG_HOME) is selected by the desktop. Its final component must be an
owned directory not writable by group/other. The fixed `knetsentry-workspace`
child is owner-only mode 0700. The `layout.v1` file must be an owned, singly
linked regular file of mode 0600. The store uses directory-relative operations,
no-follow opens, nonblocking bounded reads, and exact schema validation. A
missing, invalid or unsupported file yields balanced defaults without rewriting
it. An explicit save can repair a malformed private regular file, but refuses
unsafe existing paths. Temporary names are bounded and created exclusively.
File fsync, atomic rename and directory fsync are required for confirmed save;
failed confirmation is displayed without claiming durability. A crash before
rename leaves the previous layout intact (an orphan private temporary file may
remain). Independent app instances use last-successful-replacement semantics;
there is no cross-instance layout synchronization. This is not protection against
arbitrary code running as the same user or a compromised configuration root.

Hiding a panel is not a security policy: existing authenticated model behavior
and snapshot clearing are unchanged, including manual refresh and expiry.
No new dependencies, network operations or manager authority are introduced.

## Verification

Native contract tests all 72 valid combinations, invalid versions/values,
atomic replacement, malformed-file recovery, unsafe modes, symlinks, FIFOs and
hardlinks. The rendered desktop regression uses separate application processes
and a disposable XDG configuration root to test default windowed geometry, save, restore, compact
and wide layout, malformed-file recovery and unaffected Assets telemetry.
Other self-tests intentionally use in-memory defaults rather than operator files.

Run `ctest --preset linux-release -R '^knetsentry_(workspace_preferences_contract|gui_workspace_runtime)$' --verbose --no-tests=error`.
Strict QML analysis, all seven presets, hosted CI, and manual resize/restart
qualification remain mandatory. Native tests are in all seven presets; the
rendered process test uses the established non-sanitized desktop scope.

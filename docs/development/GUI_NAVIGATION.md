<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M1.4 — Application Shell and Primary Navigation

**Scope:** Issue #12, Ubuntu 26.04 AMD64; Qt 6 / KDE Frameworks 6 / Kirigami.
**Status:** Implementation prepared; runtime acceptance must be performed on the
supported system. Navigation is functional; **SIEM monitoring is not**.

## Intent and interaction contract

The Kirigami `GlobalDrawer` provides seven ordered top-level destinations with
both clickable actions and keyboard accelerators. It remains usable on GNOME
without installing KDE Plasma. The application initially opens **Dashboard**.

| Destination | Shortcut | M1.4 content | Operational data |
| --- | --- | --- | --- |
| Dashboard | `Ctrl+1` | Planned system and monitoring overview | None |
| Assets | `Ctrl+2` | Future authorized LAN/IoT inventory | None |
| Events | `Ctrl+3` | Future event storage and search | None |
| Detections | `Ctrl+4` | Future rule-engine results | None |
| Alerts | `Ctrl+5` | Future triage and severity findings | None |
| Investigations | `Ctrl+6` | Future incident and evidence workflow | None |
| Settings | `Ctrl+7` | Future manager-controlled storage and configuration | None |

Each selection displays a **real `Kirigami.Page`** (`SectionPage.qml`), not a
fabricated table. Every page states that no data is collected or displayed.
A persistent footer states monitoring is not active. The interface neither
starts sensors nor attempts to connect to a manager. A section's description
is a product roadmap statement, not an actual capability or health indicator.

Top-level navigation uses `pageStack.replace()` rather than `push()`. This
keeps the main page row's depth at one across repeated section changes and
avoids misleading back-history or unbounded page accumulation. Unknown section
IDs are rejected. The selected section, active page ID, and stack depth are
observable for automated, *unprivileged* GUI verification only. They are not
an authorization or privileged management interface. New operational
sections must obtain security data through approved C++/IPC integration in
future issues; they must not write into event storage directly from QML.

## Automated acceptance

On the supported Ubuntu system:

```bash
cmake --preset linux-release --fresh &&
cmake --build --preset linux-release --parallel &&
ctest --preset linux-release --output-on-failure

python3 scripts/verify_m14_navigation.py --build-dir build/presets/linux-release
python3 scripts/verify_m13_gui.py --build-dir build/presets/linux-release
python3 scripts/verify_m12_hardening.py --build-dir build/presets/linux-release
```

The new mandatory `knetsentry_primary_navigation` CTest invokes the real
executable with `--self-test-navigation` and exercises every route, verifies
active page identity and constant depth, then rejects an unknown destination.
It requires genuine Kirigami QML imports, and runs with Qt's offscreen backend.
Core-only builds **do not** qualify this test. `--self-test-qml`, `--version`
and `--help` remain available; informational flags do not require a display.

Repeat with `linux-debug`, `linux-sanitize`, and `linux-clazy` (and the
existing `linux-analysis` preset where applicable). On sanitizer builds, both
QML-only startup and navigation tests receive the *same two* documented
Fontconfig/Kirigami allocation suppressions; the original separate 1,337-byte
LeakSanitizer negative control continues to require a detectable first-party
leak. No global suppression and no `detect_leaks=0` setting are permitted.

Run all structural verifiers:

```bash
for script in scripts/verify_m*.py; do
    python3 "$script" || exit 1
done
```

Without `--build-dir`, the new M1.4 verifier checks only source structure and
must **not** be interpreted as proof of a working GUI.

## Manual GNOME verification

1. Launch `./build/presets/linux-release/apps/desktop/knetsentry` without root.
2. Confirm Dashboard appears by default and the global drawer can be opened.
3. Select **all seven** destinations through the drawer; each displays a
   distinct title and honest non-operational status.
4. Test `Ctrl+1` through `Ctrl+7`; the same pages must appear with the drawer
   closed. Revisit sections repeatedly to check for freezes or stack growth.
5. Resize the window to its supported minimum and back. Verify labels remain
   readable, navigation usable, and the footer status visible.
6. Confirm no sample security events, fake device counts, credentials, network
   scans, privileged prompts, or unintended public Internet traffic appear.
7. Confirm normal window shutdown and functional `--help`/`--version`.

KDE Plasma compatibility remains a project target but is not claimed tested
by a GNOME-only acceptance run. Full QML accessibility/navigation automation
and expanded visual testing are assigned to future GUI issues.

## Security, licensing, and limitations

This issue changes only the unprivileged Qt presentation and its test harness.
It does not modify the `TB-*` or `TH-*` threat boundaries, any `KS-NET-*`
authorization policy, private telemetry handling, raw storage location, or
approved intelligence egress. All new QML remains MIT-licensed and embedded in
the existing Qt 6 QML module. New documentation remains CC-BY-SA-4.0.

References: [KDE global drawer](https://develop.kde.org/docs/getting-started/kirigami/introduction-actions/),
[KDE PageRow](https://api.kde.org/qml-org-kde-kirigami-pagerow.html),
[M1.3 GUI foundation](GUI_FOUNDATION.md).

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

## M1.4 follow-up: page ownership and desktop diagnostics

The M1.4 GNOME manual run reported repeated `QML SectionPage: Created graphical
object was not placed in the graphics scene` messages after navigation.
This is consistent with KDE issue 501674: Kirigami `PageRow` can emit that
warning when it instantiates a `Component` directly. KnetSentry now calls
`sectionPageComponent.createObject(null, { "sectionId": sectionId })` and
passes the resulting `Kirigami.Page` object to `pageStack.replace(nextPage)`.
PageRow adopts the object. If the replacement fails, the unattached object
is destroyed rather than leaked; the active section is unchanged. This
preserves top-level stack depth one and rejects unknown route identifiers.

A second, **non-sanitizer** CTest (`knetsentry_navigation_qml_diagnostics`)
runs 28 actual route transitions and rejects the specific unplaced-SectionPage
warning. The full ASan/UBSan navigation test continues to run separately
with the existing narrow third-party LSan suppressions (no new suppressions).
To inspect it independently:

```bash
python3 scripts/check_m14_runtime_diagnostics.py --build-dir build/presets/linux-release
```

### Desktop-portal registration on GNOME

The desktop-portal error `App info not found for
'io.github.spilledmilkfactory.KnetSentry'` indicates that the unpackaged
development executable lacks a discoverable matching `.desktop` entry.
`setDesktopFileName()` alone does not install or register the desktop entry.
A separate, explicit per-user helper can register your current binary:

```bash
python3 scripts/manage_dev_desktop_entry.py --install \
    --binary build/presets/linux-release/apps/desktop/knetsentry
python3 scripts/manage_dev_desktop_entry.py --check
# Re-launch ./build/presets/linux-release/apps/desktop/knetsentry
python3 scripts/manage_dev_desktop_entry.py --uninstall  # when finished
```

The helper does not use root, run during application startup, overwrite
an unmanaged desktop entry, or change system-wide registration. Its effects
are confined to the current user's XDG applications directory. Desktop-
portal behavior depends on the user session and installed portal services;
retest in your actual GNOME session. A per-user developer registration is
**not** a substitute for future package-level desktop integration.

### Kirigami DrawerHandle binding loop

`DrawerHandle.qml: ... Binding loop ... bottomMargin` originates inside the
installed Kirigami QML module (6.24.0 in the reported run), not in
`SectionPage.qml`. This follow-up does not modify, vendor, or suppress
upstream Kirigami QML. If it remains, preserve the warning and reassess
against an updated Kirigami package or report a minimal reproducer upstream.
Disabling the drawer handle would remove an existing keyboard/mouse
navigation affordance and is not an acceptable untested workaround.
The diagnostics helper reports this message separately; use
`--check-all-warnings` for an intentionally strict external-dependency check.

## Security, licensing, and limitations

This issue changes only the unprivileged Qt presentation and its test harness.
It does not modify the `TB-*` or `TH-*` threat boundaries, any `KS-NET-*`
authorization policy, private telemetry handling, raw storage location, or
approved intelligence egress. All new QML remains MIT-licensed and embedded in
the existing Qt 6 QML module. New documentation remains CC-BY-SA-4.0.

References: [KDE global drawer](https://develop.kde.org/docs/getting-started/kirigami/introduction-actions/),
[KDE PageRow](https://api.kde.org/qml-org-kde-kirigami-pagerow.html),
[M1.3 GUI foundation](GUI_FOUNDATION.md).

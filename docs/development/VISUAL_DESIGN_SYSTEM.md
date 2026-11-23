<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M1.5 — Visual design system

**Status:** implementation foundation / pending actual Ubuntu 26.04 Qt/Kirigami acceptance.
This guide documents KnetSentry's reusable presentation primitives. It does
**not** authorize monitoring, event ingestion, changes to security policy, or
external network access.

## Goals and scope

KnetSentry is a long-running LAN security application that must never confuse
**monitoring availability**, **source confidence**, **security-event severity**,
and **verified absence of an observation**. Missing evidence cannot be represented
as a healthy or safe network. Every dashboard or metric added later must honor
that distinction and cite its source/coverage/freshness.

M1.5 retains the seven M1.4 destinations, `Ctrl+1`–`Ctrl+7`, bounded Kirigami
`PageRow` replacement, the no-fabricated-telemetry contract, unprivileged GUI,
and existing runtime/sanitizer tests. No privileged backend is introduced.

## Themes: KDE and GNOME compatibility

Qt Quick Controls and Kirigami should respect the platform's light and dark
colors. We use `Kirigami.Theme.backgroundColor`, `textColor`, and the native
Qt/Kirigami control styles for surfaces and text. This also permits real system
palette changes under KDE Plasma or GNOME and avoids hard-coding black-on-dark
or white-on-light interface text. A future in-app theme override is **not**
implemented or claimed by M1.5; the platform currently owns palette selection.

The only fixed colors are the five labeled **severity** samples below. They are
used exclusively for severity tokens, never for availability/status or system
health. Semantic severity text labels are mandatory; colors are not sufficient
by themselves. The Settings page displays these as **samples, not security alerts**.

| Severity | Background | Foreground | Static WCAG contrast target |
| --- | --- | --- | --- |
| Critical | `#991B2B` | `#FFFFFF` | At least 4.5:1 |
| High | `#994411` | `#FFFFFF` | At least 4.5:1 |
| Medium | `#755400` | `#FFFFFF` | At least 4.5:1 |
| Low | `#245C41` | `#FFFFFF` | At least 4.5:1 |
| Unknown | `#44546B` | `#FFFFFF` | At least 4.5:1 |

The offline verifier computes sRGB relative luminance and checks these pairs.
These static checks do not establish text contrast for every third-party
Kirigami style. Accessibility testing must also be performed using real GNOME
and Plasma light/dark schemes and high-contrast user settings.

## Typography, sizing, spacing and icons

`apps/desktop/DesignTokens.qml` is the **single source of truth** for our first-
party spacing and sizing values. It is embedded in the Qt module and contains
no privileged operations or data. Token choices for M1.5:

| Token | Value | Usage |
| --- | --- | --- |
| `spaceXs`, `spaceS`, `spaceM`, `spaceL`, `spaceXl` | 4, 8, 12, 20, 28 px | Inset and component spacing |
| `radiusS`, `radiusM` | 6, 10 px | Tags and information cards |
| `titleSize`, `sectionSize`, `bodySize`, `captionSize` | 27, 17, 14, 12 px | Initial hierarchy; respect future user font scaling |
| `touchTarget` | 40 px | Initial minimum target for actionable controls |
| `compactBreakpoint` | 820 px | Switch between two-card and one-card layouts |

Use KDE/Breeze/freedesktop themed icons (for example, `dialog-information`
and `network-disconnect`); do not bundle an unapproved icon pack. Never use
an icon alone to explain severity, status, or authorization. If an icon is
purely decorative, it should be ignored by assistive technologies.

## Reusable QML components

- `DesignTokens.qml`: layout, typography, motion and semantic severity values.
- `SurfaceCard.qml`: theme-aware information surfaces with text and icon.
- `StatusBadge.qml`: non-operational availability badge with accessible label,
  **not** a threat severity value.
- `SeverityBadge.qml`: severity sample with text as well as WCAG-checked color.
- `SectionPage.qml`: scrolling, responsive, platform-themed pages for all seven
  destinations, including clearly marked severity **examples only** in Settings.

Avoid duplicating token constants across page implementations. Only future
approved source models may populate actual event, asset and alert views.

## Responsive layouts

`SectionPage.qml` uses a clipped vertical `Flickable` and a `Flow`. Information
cards become a single column below the 820 px threshold. Content may scroll
instead of overlapping or truncating. Validate at approximately 700, 820 and
1100 px window widths, with long labels and increased desktop font scaling.
A narrow window's geometry is **not** proof of mobile support.

## Accessibility foundations

- Use readable text labels, not color-only indicators.
- Attach meaningful accessibility names to status/severity badges.
- Retain keyboard-based `Ctrl+1`–`Ctrl+7` navigation and visible system focus.
- Use native Qt/Kirigami control styling, preserving platform foreground,
  background and focus colors.
- Do not imply security coverage from missing telemetry or from a green color.
- Test light/dark and high-contrast appearance manually. M1.5's static contrast
  verifier only covers fixed severity pairs, not every possible theme or font.

## Motion and reduced motion

Any future transitions should default to subtle, nonessential motion: 120 ms
for quick feedback and 180 ms for common transitions. **Reduced motion** must
use the defined zero-duration token and avoid flashing, animated critical
severity, or constant attention-grabbing movement. This milestone adds **no
status animation** (`animateStatusChanges: false`), so there is currently no
in-app reduced-motion toggle to test or persist. Future animation must include
explicit opt-out/system-preference handling and a testable static fallback.

## M1.5 QML color-type import correction

Qt Quick supplies the QML `color` value type used by the six strongly typed
severity-token properties in `DesignTokens.qml`. A file importing only
`QtQml` may pass C++ compilation and static color-contrast inspection while
failing at **QML instantiation** with `color is not a type`. The token module
therefore imports `QtQuick` explicitly (in addition to `QtQml`).

The offline `verify_m15_visual.py` now requires that import and all six typed
properties. Removing `import QtQuick` is a supported negative test: the offline
verifier must fail even without access to a QML runtime. The real desktop
`knetsentry_kirigami_qml_startup`, `knetsentry_primary_navigation`, and
`knetsentry_visual_system` tests remain mandatory for supported full builds.

A successful static verification is **not** evidence of a running GUI. The
corrected Qt/Kirigami desktop must be reconfigured, compiled, tested and
manually inspected on Ubuntu 26.04 AMD64 before M1.5 is accepted.

## Ubuntu 26.04 acceptance

Run the full Qt desktop configurations, not only the `linux-core-only` build:

```bash
cmake --preset linux-release --fresh && cmake --build --preset linux-release --parallel && ctest --preset linux-release --output-on-failure
cmake --preset linux-debug --fresh && cmake --build --preset linux-debug --parallel && ctest --preset linux-debug --output-on-failure
cmake --preset linux-sanitize --fresh && cmake --build --preset linux-sanitize --parallel && ctest --preset linux-sanitize --output-on-failure
cmake --preset linux-clazy --fresh && cmake --build --preset linux-clazy --parallel && ctest --preset linux-clazy --output-on-failure
python3 scripts/verify_m15_visual.py --build-dir build/presets/linux-release
python3 scripts/verify_m12_hardening.py --build-dir build/presets/linux-release
for script in scripts/verify_m*.py; do python3 "$script" || exit 1; done
```

The additional `knetsentry_visual_system` offscreen CTest is registered in
**non-sanitized** desktop configurations only. Sanitized QML startup and
navigation remain covered by the existing two tests with their strictly
scoped third-party LSan rules; the existing deliberate-leak test remains
mandatory. We do **not** expand the scope of the M1.3 suppression file.

Manual GUI acceptance: inspect all seven destinations, mouse drawer and
keyboard shortcuts, narrow/wide resizing, light and dark system themes,
contrast of labels/badges, Settings severity samples, and scroll behavior.
Verify that all monitoring notices remain accurate and the application never
claims real security data. The external Kirigami `DrawerHandle.qml` binding
loop remains tracked separately; M1.5 does not hide or patch upstream warnings.

## Future work and limits

No theme preference persistence, user custom palette, font zoom control,
readable high-contrast accessibility audit, animation framework, telemetry,
active system status, or KDE incubation acceptance is claimed for M1.5.
These require later implementation and real platform qualification.

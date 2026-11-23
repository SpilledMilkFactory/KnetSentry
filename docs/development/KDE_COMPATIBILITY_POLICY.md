<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — KDE and GNOME Compatibility Policy

**Status:** M0.6 application-policy baseline; intended compliance, not a KDE endorsement or installed/verified GUI.

## 1. Product and community scope

The initial product is an independent GitHub-hosted Ubuntu 26.04 AMD64 application. It uses **Qt 6, Qt Quick/QML, KDE Frameworks 6 and Kirigami** for the desktop, but must remain usable under both GNOME and KDE Plasma. No KDE Plasma session, privileged graphical desktop, or online service is necessary for core operation. The manager, sensors and optional agents do not depend on Qt Quick/Kirigami. Follow KDE's Human Interface Guidelines and accessibility recommendations without implying official KDE membership.

## 2. Desktop engineering commitments

- Use ECM/CMake and Qt's supported QML module registration appropriately; validate actual installed versions against Ubuntu 26.04.
- Prefer system-aware palettes, accessible contrast, scalable typography, keyboard operation, reduced-motion support, and stable focus behavior.
- Keep event models and privileged state in C++/manager services behind authorized IPC, not privileged QML.
- Install validated desktop metadata, AppStream metainfo, icons and localized strings when implementation reaches M15.
- Maintain translation extraction and accessible application naming as KDE Review becomes relevant; include source/editable form for assets.
- Test Qt/Kirigami startup and core workflows under GNOME as well as KDE Plasma, on supported package sets; no unreviewed GUI dependencies in agents/services.
- Do not assume Qt modules have the same licenses: some optional Qt open-source components are GPL-only (e.g. Qt Graphs) and require separate compatibility approval.

## 3. KDE adoption is a separate external process

M16 may pursue KDE Incubation and KDE Review, with sponsor, KDE Invent/GitLab CI, REUSE lint, project governance, AppStream metadata, localization and other requirements in force at the time. **M16 is not an automatic result of Qt adoption**, and KnetSentry must not claim to be an official KDE project before acceptance. Keep application identifier `io.github.spilledmilkfactory.KnetSentry` provisionally until an actual KDE migration requests a change. Preserve GNOME compatibility during that work.

## 4. Compliance review gates

| Milestone | Deliverable |
|---|---|
| M1.1/M1.3 | Real Qt/KF6/Kirigami modules and ECM versions approved and built on Ubuntu 26.04 |
| M1.8 | CMake, Qt/QML tests, Clazy where applicable, license metadata and `reuse lint` in CI |
| M8 | Performance, accessibility, reduced motion, keyboard operation, safe models |
| M15.6/M15.7 | GNOME and KDE Plasma installation and desktop-integration acceptance evidence |
| M16 | Actual KDE sponsor/review, infrastructure and community requirements |

References: https://community.kde.org/Policies/Licensing_Policy ; https://develop.kde.org/docs/getting-started/add-project/incubation/ ; https://develop.kde.org/docs/getting-started/add-project/review/ ; https://develop.kde.org/hig/ .

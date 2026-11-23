<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0004 — Qt Quick/Kirigami is a Presentation Boundary

**Status:** Accepted for M0.4 design; implementation unverified.
**Context:** KnetSentry targets both GNOME and KDE Plasma on Ubuntu 26.04.
The security system must run independently of an interactive desktop, and an
operator interface must not inherit capture or manager-admin privileges.

## Decision

- Qt 6, Qt Quick/QML, KDE Frameworks 6 and Kirigami are used in the
  unprivileged desktop `P-02` only; graphical components never become
  dependencies of manager, agent, transport, capture or feed services.
- `C-20` converts typed, authorized, paginated manager responses (`I-23`) to
  QML data models; QML does not issue SQL or bypass `I-01` authorization.
- KDE's usability, accessibility and localization requirements shape the
  interface; GNOME compatibility is tested independently. Plasma is not a
  runtime requirement for GNOME installs.
- Real/partial/unknown coverage is prominently represented in the UI.
  Optional AI output is labeled as suggestion, not verified evidence.

## Consequences and alternatives

The GUI needs additional IPC and C++ model work. Root GUI, direct SQLite
access, embedded capture and unverified "all clear" status are rejected.
A second Qt GUI is not planned for later KDE adoption.

**Revisit:** M1.3/M1.4, M2.6, M6.8, M8, M15.6, M16. Related
`TB-05`, `TB-12`, `TH-011`, `TH-019`, `TH-038`.

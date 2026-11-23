<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0006 — MIT Application, REUSE Licensing, and Gated Dependencies

**Status:** Accepted as a policy decision in M0.6; implementation and redistribution validation pending.

## Context

The GitHub repository began under MIT. The issue template mentioned GPL-3.0-or-later, but KDE's published policy also allows MIT application code and sets specific terms for documentation and CMake files. KnetSentry's future Qt 6, KF6/Kirigami, capture, TLS, feed, and optional AI stack may have module-specific rights and distribution obligations.

## Decision

Keep root `LICENSE` MIT **unchanged**. Use MIT for KnetSentry-authored executable/source/tooling files; CC-BY-SA-4.0 for current/revised Markdown documentation; BSD-2-Clause for future custom CMake code. Use SPDX declarations, REUSE metadata and license texts in `LICENSES/`. Prior MIT grants to documentation remain valid. Defer **approval of exact third-party artifacts** until their version, dependency graph, license obligations and distribution method are known. Treat GPL-only Qt add-ons, AI weights and detection corpora as review-required, not silently approved. Maintain the independent Qt/Kirigami KDE/GNOME desktop objective; KDE Incubation and KDE Review remain M16.

## Alternatives considered

- Replacing all KnetSentry code with GPL-3.0-or-later: valid for many KDE applications but not required by KDE; changes the existing public licensing decision without an identified need.
- Using MIT for all documentation/CMake: inconsistent with KDE's current component-specific licensing guidance for a project seeking eventual adoption.
- Treating Qt/KF6 and all public datasets as universally approved: invalid because module licenses and dataset/model terms differ.

## Consequences

Mixed file licenses require explicit SPDX notices and complete license texts. Historical documentation MIT rights remain available. Every new dependency requires a scoped decision and eventual artifact-derived redistribution audit. Before adding source files for KDE adoption, the maintainer must select a publication-safe copyright contact email (not assumed here). Official REUSE lint becomes a mandatory CI gate in M1, while M0.6 has only an offline consistency verifier.

See [licensing policy](../../development/LICENSING_POLICY.md), [dependency policy](../../development/DEPENDENCY_APPROVAL_POLICY.md), and [KDE policy](../../development/KDE_COMPATIBILITY_POLICY.md).

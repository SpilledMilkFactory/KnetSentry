<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Maintainer Roles and Continuity

## Current roles

- **Repository owner / lead maintainer:** `SpilledMilkFactory`. Decides roadmap priorities, approves routine PRs, coordinates security response, manages release privileges, and maintains dependency/license records.
- **Security triage lead:** Initially the same maintainer. The role receives private vulnerability reports through GitHub when private reporting is enabled, controls embargo discussions, tracks affected versions and remediation, and limits exposure of evidence.
- **Contributors:** Submit licensed, attributable changes and verify them in a safe test environment; contributions do not automatically confer security permissions or merge authority.
- **Reviewers:** Named by the maintainer for particular changes; their authority and independence must be explicit. A GitHub `CODEOWNERS` match requests review where GitHub settings support it; it does **not** prove approval or effective branch protection.

## Review independence

Until a second trusted maintainer is available, the lead may perform documented self-review. Critical/high security changes should seek separate competent review before release when practical. The absence of independent review is a named limitation and may block a release decision; it must not be marked as an independently passing control.

## Delegation and continuity

Before delegating, verify the candidate's identity, contribution history, security understanding, and minimum required GitHub role. Do not share personal access tokens, signing keys, or credentials. Add access using native repository/organization permissions and record role changes. Remove access promptly when no longer required.

In the event of maintainer unavailability, record the limitation publicly **without disclosing embargoed reports**; no contributor should assume administrative or release authority. Future continuity planning, transfer of ownership, and any KDE migration require explicit documented approval and secure handover of private findings and release keys. KDE project designation has separate community governance commitments.

## Conduct concerns

A confidential conduct contact separate from vulnerability intake has not been configured. See [the Code of Conduct](../../CODE_OF_CONDUCT.md) and [repository configuration checklist](../development/REPOSITORY_ADMIN_CHECKLIST.md). GitHub's own reporting facilities are an alternative for platform abuse, especially if the maintainer is the subject of a report.

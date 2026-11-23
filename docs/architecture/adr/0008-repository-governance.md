<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0008 — Repository Governance and Coordinated Disclosure

**Status:** Accepted policy design at M0.8; GitHub settings require maintainer confirmation.

## Context

KnetSentry is a public, security-sensitive project with one current maintainer. Public GitHub issues are unsuitable for exploit details or private LAN evidence. Earlier milestones established secure development gates but not a complete contribution/disclosure workflow.

## Decision

Adopt public contribution and conduct policies, GitHub issue forms that keep sensitive reports out of public workflows, a separate controlled vulnerability-reporting process using GitHub private advisories **when enabled**, and explicit single-maintainer governance. Require provenance and per-file license compatibility. Track GitHub-side settings as human actions, not results of a file patch. Maintain separation between reviewer requests, actual code approval, independent security review, and release authority.

## Alternatives and tradeoffs

- **Publish a generic security email address:** rejected because no verified managed mailbox was provided; it would misdirect sensitive reports.
- **Use public security-labeled issues:** rejected because labels do not make reports confidential.
- **Require two independent approvals immediately:** rejected as an unenforceable promise for the present single-maintainer project; independence limitations must still be documented and considered at release.
- **Introduce a Contributor License Agreement:** unnecessary for the accepted MIT/CC-BY-SA-4.0/BSD-2-Clause contributions policy; explicit licensing provenance remains required.

## Consequences and follow-up

M0.8 supplies documentation/templates and an offline verifier, while the owner manually enables private vulnerability reporting and notification settings. M1.8/M1.9 later implement actual CI/ruleset safeguards. KDE Incubation (M16) may introduce further governance and infrastructure requirements. Revisit this ADR when maintainer roles, intake methods, licensing, or platform capabilities change.

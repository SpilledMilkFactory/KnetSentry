<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry Repository Governance

**Issue:** M0.8 / GitHub #8. **State:** policy and repository templates only; GitHub settings and human response capabilities require separate owner confirmation.

## Maintainer and decision model

KnetSentry is currently maintained by [SpilledMilkFactory](https://github.com/SpilledMilkFactory), the repository owner. The owner controls issue triage, merges, security embargoes, dependency approvals, roadmap changes, and release authorization. Contributors propose changes; reviewers can recommend acceptance or rejection, but ownership/maintainer status is not implied by participation. A written [maintainer role policy](docs/governance/MAINTAINER_ROLES.md) governs delegation and continuity.

The initial maintainer may review their own work when no other trusted reviewer is available. Every such action must be labeled *self-review*, not independent security review. High-risk changes should seek an independent reviewer whenever feasible; unresolved independence limits remain documented for M13/M15 release sign-off. Public issue comments never constitute approval to run capture, change firewall policy, scan networks, or publish data.

## Decision and change lifecycle

- Roadmap milestones and labels represent planning. Proposed changes should be tied to an issue, a branch, and a focused PR with the verification evidence actually available for the current development stage.
- Requirements, trust-boundary changes, and architecture decisions require updated design documentation/ADRs; security review follows the [development contract](DEVELOPMENT_CONTRACT.md) and [impact procedure](docs/development/SECURITY_REVIEW_PROCESS.md).
- A maintainer may reject, postpone, or split a contribution with rationale. Sensitive bugs are handled in a **private advisory**, not the public project board.
- Untrusted PR code receives no secrets or privileged local network access. Branch restrictions and required checks activate only once GitHub-side settings and workflows are verified.
- Releases require separate approval and artifact-specific evidence, not merely a green PR badge. No published v1.0.0 artifacts currently exist.

## Governing policies

- [Contributions](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), and [Security reporting](SECURITY.md).
- [Vulnerability handling](docs/security/VULNERABILITY_HANDLING.md) and [repository configuration checklist](docs/development/REPOSITORY_ADMIN_CHECKLIST.md).
- [Licensing](docs/development/LICENSING_POLICY.md), [dependency approval](docs/development/DEPENDENCY_APPROVAL_POLICY.md), and [KDE compatibility](docs/development/KDE_COMPATIBILITY_POLICY.md).
- The project remains independent of the KDE organization until formal adoption is approved.

## Traceable M0.8 governance requirements

| ID | Topic | Requirement | Verification |
| --- | --- | --- | --- |
| `KS-GOV-001` | Ownership and scope | Project ownership and scope of decision authority are documented. | `GOV-01` |
| `KS-GOV-002` | Roles and delegation | Maintainer, contributor, reviewer, and security triage responsibilities are distinguished. | `GOV-02` |
| `KS-GOV-003` | Single-maintainer disclosure | Self-review is identified and cannot masquerade as independent review. | `GOV-03` |
| `KS-GOV-004` | Change acceptance | PRs reference an issue and record scope, verification, and risk before merge. | `GOV-04` |
| `KS-GOV-005` | Review escalation | Security-boundary or privilege changes follow the dedicated security-review policy. | `GOV-04` |
| `KS-GOV-006` | Responsible contribution | All contributions identify provenance and comply with the applicable per-file licenses. | `GOV-05` |
| `KS-GOV-007` | No obligatory CLA | The project does not impose an undisclosed CLA or copyright assignment. | `GOV-05` |
| `KS-GOV-008` | Public input segregation | Public issue forms prohibit exploitable findings and private telemetry. | `GOV-06` |
| `KS-GOV-009` | Private vulnerability channel | Maintainers enable and test GitHub private vulnerability reporting before claiming confidential intake. | `GOV-07` |
| `KS-GOV-010` | Fallback contact accuracy | No nonexistent security mailbox or unverified confidentiality guarantee is published. | `GOV-07` |
| `KS-GOV-011` | Coordinated disclosure | Triage, collaboration, remediation, and release advisory decisions remain controlled. | `GOV-08` |
| `KS-GOV-012` | Data minimization | Issue forms, CI artifacts, and disclosures exclude unnecessary secret or personal information. | `GOV-06` |
| `KS-GOV-013` | Conduct standards | Participants can find project conduct expectations and a non-public reporting path. | `GOV-09` |
| `KS-GOV-014` | Process continuity | Maintainer absence, handover, and repository governance changes have documented procedures. | `GOV-10` |
| `KS-GOV-015` | Code ownership | CODEOWNERS declares current maintainer responsibility without pretending external approvals. | `GOV-02` |
| `KS-GOV-016` | Branch protection staging | Branch rules and required status checks are enabled when available and functioning. | `GOV-11` |
| `KS-GOV-017` | Release authority | Publishing/signing privileges are separate from ordinary pull request review. | `GOV-11` |
| `KS-GOV-018` | Confidential findings | Security reports are not leaked through public issues, labels, projects, or PR artifacts. | `GOV-08` |
| `KS-GOV-019` | KDE independence | KDE-compatible intent is not described as present official KDE project status. | `GOV-12` |
| `KS-GOV-020` | Verification honesty | Repository settings and responder availability are listed as manual, unverified tasks until confirmed. | `GOV-12` |

These policies define intended behavior. `scripts/verify_m08_governance.py` checks **file and document consistency only**, not whether private vulnerability reporting, branch rules, notifications, or response personnel have actually been configured.

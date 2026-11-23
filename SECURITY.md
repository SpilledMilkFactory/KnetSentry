<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry Security Policy

## Project status and supported versions

KnetSentry is currently **pre-release design documentation**. There is no production SIEM executable, supported package, release branch, or security support SLA. A listed milestone is not a released security control. Future release-support periods and maintained versions will be documented when packages are published.

| Version | Security support status |
| --- | --- |
| `main` (pre-release design) | Best-effort review of repository and development-process vulnerabilities; no production guarantee |
| v1.0.0 | **Not released**; support policy to be defined before publication |

## Privately report a suspected vulnerability

**Do not open a public GitHub issue, discussion, or pull request revealing an exploitable security flaw or proof of concept.** Please visit the repository's [Security Advisories page](https://github.com/SpilledMilkFactory/KnetSentry/security/advisories) and choose **Report a vulnerability** *if private vulnerability reporting is enabled*. Include a concise impact statement, relevant component and revision, authorized sanitized reproduction steps, and any proposed fix or mitigations. Avoid live LAN logs, credentials, actual private addresses, or sensitive evidence unless an explicitly agreed safe transfer method exists.

**Enablement is a maintainer action, not accomplished by this file.** Until the button is available, ask the repository owner for a private security contact via the [GitHub profile](https://github.com/SpilledMilkFactory) **without public vulnerability details**. The owner should configure an appropriate alternate confidential contact before accepting public vulnerability submissions; this repository does not invent or publish an unverified email address. If no safe channel is available, do not post exploit details publicly.

## Coordinated disclosure procedure

- The maintainer privately triages scope, impact, affected versions/branches, prerequisites, and reproducibility; duplicate or out-of-scope reports receive an explanation where possible.
- Use a private advisory or other access-controlled collaboration space for discussion, patches, and proof of concept. Do not move confidential reports into normal public issue templates.
- Assess potential compromise and exposure; reduce harm, prepare remediation, and add safe regression tests. For serious findings, prioritize containment and notify appropriate affected parties.
- Coordinate a reasonable disclosure timeline with the reporter and affected downstream projects; avoid rigid embargo promises or guaranteed response times. Communicate progress when feasible.
- Publish security advisories, credits, affected/fixed version information, and validated fixes when it is safe and useful to do so. Do not claim a vulnerability is fixed without applicable verification.
- Retain a limited, access-controlled audit record; remove unnecessary private data from public artifacts.

### Responsible testing boundaries

Only test devices, systems, and networks you own or have explicit written authorization to assess. No third-party probing, denial-of-service, persistence, data theft, social engineering, or broad scanning is authorized by KnetSentry's security-reporting policy. Report observations with minimal impact; stop if testing risks harming a production environment. This document is not permission to test other systems, and it does not promise legal safe harbor.

## Other requests

For ordinary functional defects, use the [public bug form](.github/ISSUE_TEMPLATE/bug_report.yml) **only after removing sensitive security details**. For code changes that affect security properties, follow [security review](docs/development/SECURITY_REVIEW_PROCESS.md). The maintainers' internal handling plan is documented in [vulnerability response process](docs/security/VULNERABILITY_HANDLING.md).

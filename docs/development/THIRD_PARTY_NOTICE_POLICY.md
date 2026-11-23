<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Third-Party Notices and Release Clearance

**Status:** M0.6 policy. No redistributable third-party package or model has been approved by this issue.

## Before each release

1. Enumerate **actual release payloads** (all `.deb` packages, desktop/runtime dependencies bundled, QML modules, libraries, tools, data, models, icons, notices and source archives).
2. Match each component to the approved [dependency register](DEPENDENCY_REGISTER.md), resolved version, upstream provenance and source/build artifact digests.
3. Determine whether a component is **system provided**, **dynamically linked**, **copied source**, or **bundled**; apply its actual obligations, not guessed upstream descriptions.
4. Include required source-availability information, copyright and license notices, LGPL replacement/relink rights as applicable, and attribution for redistributable feeds/rules/models.
5. Resolve unknown transitive dependencies, conflicting obligations and unapproved proprietary assets **before** publishing; unreviewed entries are release blockers.
6. Produce an artifact-derived SBOM and exact checksums, and retain CI/build provenance and documented rights decisions.
7. Validate clean-system install/upgrade, repository release archives and the evidence reported to the user. Passing source-only REUSE lint is not the same as final redistribution clearance.

## Exception policy

Any exception needs reviewer, documented rationale, scope, expiration/revisit trigger, exact artifacts and evidence of authorization. Never issue a blanket distribution sign-off for products not yet packaged. Model weights and feed contents require the same source-and-terms discipline as binaries.

## Templates

For each distributed component record: `Name | Version | Hash | Source | SPDX expression | Inclusion mode | NOTICE file | Source provision | Redistribution decision | Reviewer/date`.

At M15.5 require `APPROVED_FOR_DISTRIBUTION` for **each** bundled artifact; do not infer it from `APPROVED_FOR_BUILD`. Track M13.7 source/supply-chain security review separately from legal/redistribution decisions.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Contributing to KnetSentry

KnetSentry welcomes good-faith contributions to the open-source **design-stage** LAN SIEM. The current repository contains requirements, planned security controls, and offline document verifiers; **production C++/Qt components and CI have not been implemented**. The [development contract](DEVELOPMENT_CONTRACT.md) activates build and security tests as their milestones arrive.

## Before opening an issue or pull request

1. Read the [Code of Conduct](CODE_OF_CONDUCT.md), [security policy](SECURITY.md), and [governance policy](GOVERNANCE.md).
2. Search existing issues and milestones for similar work. Refer to the relevant `M<n>.<n>` issue; create a proposal when the change is outside the roadmap.
3. **Never post suspected exploitable vulnerabilities, credentials, private network configurations, private traffic captures, or identifiable security evidence in public issues or PRs.** Follow [private disclosure](SECURITY.md).
4. Work only with devices and networks you own or are explicitly authorized to test. Use sanitized or synthetic examples in public reviews.
5. Identify changes to monitoring scope, outbound intelligence egress, packet parsing, privileges, storage, and response actions for security review.

## Changes and review

- Branch from the accepted `main` baseline; keep each PR focused on one issue where practical. Use conventional commits with the milestone identifier, e.g. `docs(governance): ... (M0.8)`.
- Explain intent, affected interfaces/trust boundaries, planned or executed tests, known risks, and documentation updates in the [PR template](.github/pull_request_template.md).
- Run the verification steps that **exist for the changed revision**. At M0 use the applicable `scripts/verify_m*.py` checks and `git diff --check`. Never mark future CTest, Qt, sanitizer, packet capture, or CI checks as passed.
- Security-impacting changes follow [security review](docs/development/SECURITY_REVIEW_PROCESS.md) and [evidence conventions](docs/development/VERIFICATION_EVIDENCE.md).
- Maintainers may request changes, split scope, or decline contributions for safety, incompatibility, licensing, or maintainability reasons, with an explanation where feasible.

## License and provenance

Contributors retain their copyrights and license **original KnetSentry application code/scripts under MIT** and **documentation under CC-BY-SA-4.0**, consistent with the [licensing policy](docs/development/LICENSING_POLICY.md). Future original CMake files use BSD-2-Clause. Include copyright and SPDX declarations. By submitting a contribution, you represent that you have the necessary rights to provide it under the applicable license. **No Contributor License Agreement or copyright assignment is required.** Do not paste third-party code or include captured traffic, rules, fonts, icons, models, or other material without provenance and reviewed compatible terms.

Dependencies start as [candidates](docs/development/DEPENDENCY_REGISTER.md); submit an approval review before introducing or packaging a new dependency. See [dependency policy](docs/development/DEPENDENCY_APPROVAL_POLICY.md).

## Community conduct and collaboration

Assume good faith; critique code, not people. See [Code of Conduct](CODE_OF_CONDUCT.md) for confidential conduct reporting. The project currently has a single maintainer; a maintainer review is **not independent review**. Future reviewers will be designated as contributors join. M1 will implement the actual C++/Qt development workflow and CI.

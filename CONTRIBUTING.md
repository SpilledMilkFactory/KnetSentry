<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Contributing to KnetSentry

KnetSentry welcomes contributions to an **early, non-operational** C++23/Qt 6
security application. A GUI, typed diagnostics, CTest/Qt Test suites, and nine
GitHub Actions CI checks exist, along with the lifecycle-only manager, local IPC,
audit logging and network authorization foundations. Packet sensors, operational
endpoint agents, security event indexing and detection do **not** exist yet.
See [project status](docs/PROJECT_STATUS.md) for current capability and evidence.

**First-time contributors:** follow the step-by-step
[Ubuntu 26.04 developer quickstart](docs/development/CONTRIBUTOR_QUICKSTART.md)
to install dependencies, build, run CTest and official REUSE lint, and start
the unprivileged Kirigami GUI. The [test suite reference](docs/development/TEST_SUITE_FOUNDATION.md)
and [CI guide](docs/development/CI_IMPLEMENTATION_M18.md) explain the gates.

## Before opening a public issue or PR

1. Read the [Code of Conduct](CODE_OF_CONDUCT.md), [security policy](SECURITY.md),
   and [governance policy](GOVERNANCE.md).
2. Search [existing issues](https://github.com/SpilledMilkFactory/KnetSentry/issues)
   and the roadmap; link your work to an issue and appropriate milestone.
3. **Never publish security vulnerabilities, exploit steps, credentials,
   private LAN details, packet captures or identifiable incident evidence** in
   public issues/PRs. Use the [private advisory route](SECURITY.md).
4. Test only devices and networks you own or have explicit authorization to
   assess. CI and contribution examples must use synthetic, sanitized data.
5. Identify changes to monitoring scope, outbound intelligence egress, packet
   parsing, privileges, file storage, and response actions as security reviews.

## Implementation and review workflow

- Branch from the latest accepted `main` and make focused changes. Use a
  conventional commit with the issue milestone, such as
  `test(core): strengthen input validation (M1.9)`.
- Use the existing [PR template](.github/pull_request_template.md): describe
  functionality, affected `TB-*`/`TH-*`/`KS-NET-*` contracts (or explicitly
  state none changed), dependency/licenses, risk, negative tests and evidence.
- Run relevant compiled tests and policy checks from the
  [contributor quickstart](docs/development/CONTRIBUTOR_QUICKSTART.md). Run
  `git diff --check`, `reuse lint`, and all applicable Python verifiers.
- Qt/KDE desktop PRs must qualify with a desktop preset; core-only passing
  never replaces QML/Qt Test execution. An inventory check proves test
  executables exist; **only CTest execution proves they passed**.
- Report `PASS`, `FAIL`, `BLOCKED`, `PLANNED`, `EXCEPTION`, or
  `NOT_APPLICABLE` honestly. Do not claim hosted CI success on a revision
  until its actual GitHub check results have passed.
- Changes affecting security boundaries require the
  [security-review procedure](docs/development/SECURITY_REVIEW_PROCESS.md).
  See [evidence conventions](docs/development/VERIFICATION_EVIDENCE.md).
- Maintainers may request revisions, split scope, or decline changes for
  security, licensing, or maintenance reasons, with explanation when safe.

## Licensing and provenance

Original KnetSentry application code and Python tools use **MIT**;
documentation uses **CC-BY-SA-4.0**; new original CMake modules use
**BSD-2-Clause**. Include applicable SPDX header declarations. Contributors
retain copyright and represent that their contributions are licensed under
these terms. There is **no CLA or copyright assignment**.

Do not paste third-party source, install captured proprietary detection
rules, add AI weights, icons, fonts, or bundle binaries without provenance,
license compatibility review and appropriate dependency approval. Passing
REUSE lint does not constitute redistribution clearance. See the
[licensing](docs/development/LICENSING_POLICY.md) and
[dependency approval](docs/development/DEPENDENCY_APPROVAL_POLICY.md) policies.

## Community and security response

The project currently has a single maintainer; their review of their own
changes is **self-review**, not independent security assessment. Follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Conduct complaints have separate
handling from security vulnerabilities; see each policy. Private vulnerability
reporting has been enabled by the maintainer, but reporting availability and
response arrangements must be confirmed on GitHub; no response SLA or
production security support is promised.

KnetSentry follows KDE-compatible design guidance but is not an official KDE
project. No release artifacts or redistribution rights are implied by a green
build or contribution.

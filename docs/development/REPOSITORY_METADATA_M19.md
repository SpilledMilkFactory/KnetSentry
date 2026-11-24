<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M1.9 — Repository metadata and contributor documentation audit

**Issue:** #17 — Establish Repository Metadata and Contributor Documentation.

## What is already implemented and retained

| Asset | Audit conclusion |
| --- | --- |
| `README.md` | Updated to current M1.8/M1.9 development state; links to reproducible contributor commands. |
| `LICENSE`, `LICENSES/`, `REUSE.toml` | Existing per-file MIT, CC-BY-SA-4.0 and BSD-2-Clause model retained; official `reuse lint` is mandatory. |
| `.github/ISSUE_TEMPLATE/` | Existing bug, feature and documentation forms retained, with public-security caution and private routing. |
| `.github/pull_request_template.md` | Existing structured security-impact, verification and reviewer-status template retained unchanged. |
| `.github/CODEOWNERS` | Existing maintainer ownership retained; no claim of independent review. |
| `CONTRIBUTING.md` | Updated to reflect actual C++/Qt implementation and CI, with quickstart, branch and PR process. |
| `SECURITY.md` | Corrected from docs-only status to pre-release application foundation; describes private advisory reporting honestly. |
| `CODE_OF_CONDUCT.md`, `GOVERNANCE.md` | Existing governance retained; no unverified confidentiality contacts invented. |
| `docs/development/CONTRIBUTOR_QUICKSTART.md` | New: reproducible supported-host setup, CMake/CTest, sanitizer, REUSE and GUI validation. |
| `docs/development/CI_EFFICIENCY_M19.md` | New: package profile policy and cache decision with explicit risks. |

The user previously reported enabling GitHub private vulnerability reporting and
all nine M1.8 Actions PR jobs passing, but these facts do not establish that
any required-check ruleset or conduct mailbox is currently configured.

## Suggested public GitHub metadata (maintainer applies manually)

- **Repository description:** `KDE-compatible, local-first LAN security intelligence and SIEM (in development; Qt 6/C++23, agentless-first).`
- **Homepage:** leave unset until a maintained official project site exists;
  do not infer a production download page from a development repository.
- **Topics:** `siem`, `cybersecurity`, `network-security`, `qt6`, `kirigami`,
  `cpp23`, `ubuntu`, `open-source`. These are optional metadata tags, not
  capabilities or promises of official KDE affiliation.
- **License badge:** GitHub should recognize the root MIT license; detailed
  per-file docs/tools licensing is specified by REUSE. A single license badge
  does not imply all repository content shares that license.
- **About / support:** do not claim v1.0.0, enterprise support, completed AI,
  fully passive network visibility, or official KDE product status.

The M1.9 patch does not mutate GitHub repository settings. They must be checked
manually by the owner under the repository **About** and **Settings** controls.

## Contributor acceptance gate

A first-time contributor on a fresh Ubuntu 26.04 AMD64 system should be able
to follow [CONTRIBUTOR_QUICKSTART](CONTRIBUTOR_QUICKSTART.md) without private
machine paths or tooling outside distribution packages, then demonstrate:

1. Desktop Release configure/build: success and **13/13 CTests**.
2. Full ASan/UBSan build: **10/10 CTests**, including LSan negative control.
3. Actual offscreen QML startup, Qt Test model, and application lifecycle.
4. `reuse lint`: success under the current spec.
5. All applicable `scripts/verify_m*.py`: success.
6. Manual unprivileged launch on GNOME/Plasma with seven navigation sections
   and clear *monitoring unavailable* presentation.
7. Public PR using the established template, honest per-revision evidence,
   explicit security impact and no private telemetry.

M1.9 automation checks the commands, source links, license metadata and CI
profiles, **not** a fresh Ubuntu desktop environment. Only the maintainer or
another authorized tester can supply actual fresh-machine build evidence.

## Follow-up boundaries

M1.9 does not enforce a new PR ruleset, implement production packet capture,
expand supported operating systems, audit deployed dependency licenses for
redistribution, create a release or configure a dedicated conduct-reporting
mailbox. These remain separate owner decisions and future milestones.

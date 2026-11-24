<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M1.8 — Ubuntu 26.04 GitHub Actions qualification

**State:** Implemented workflow, **unverified on GitHub-hosted runners** until
all required Actions jobs execute against the final PR commit. This document
is not evidence of a successful Actions run.

## Scope

The workflow `.github/workflows/ubuntu-26-04.yml` runs for PRs, pushes to main,
and manual dispatch. Every job uses `ubuntu-26.04`, explicit `contents: read`,
SHA-pinned checkout with `persist-credentials: false`, no secrets, no publish
permissions, no Docker, and no access to real monitoring interfaces or home-LAN
telemetry. Runner provisioning uses Ubuntu archive packages and will record
actual resolved versions in the GitHub log; it is not yet a version-locked
release build or redistribution approval. Dependency approvals remain governed
by the existing register.

The seven build matrix lanes are `linux-release` (13 CTests), `linux-debug`
(13), `linux-sanitize` (10), `linux-clazy` (13), `linux-analysis` (13),
`linux-core-only` (5), and `linux-sanitize-core-only` (6). The job must configure,
compile, check binary presence against CTest inventory, run **all** CTests,
and verify hardening. The sanitizer presets retain existing first-party leak
negative controls and their specifically scoped QML third-party exceptions.
There are no mandatory real-network tests at M1.8.

The `policy` job executes all documentation verification scripts, source
formatting **hygiene** (trailing whitespace/newlines, not yet a complete
clang-format style baseline), the M1.8 workflow-security source checker, and
the **official** `reuse lint` tool. The separate `qml` job runs the Qt-generated
`knetsentry_qmllint` target using distribution-provided Qt/Kirigami packages.
QML-lint failures must be resolved rather than silently ignored; initial CI
baseline behavior is not yet observed. `clang-tidy` and Clazy operate through
existing actual build presets, not merely through version commands.

No test results or binaries are uploaded by default, to reduce the chance of
publishing sensitive absolute paths, diagnostic data or future fixtures. Build
failure is preserved and cannot be converted into success by missing tools,
zero tests or `continue-on-error`.

## Local source validation

```bash
python3 scripts/verify_m18_ci.py --format
for script in scripts/verify_m*.py; do python3 "$script" || exit 1; done
reuse lint
```

GitHub runners alone establish whether packages, clang-tidy/Clazy, Qt-generated
QML lint, all seven build/test lanes and policy checks run successfully.

## Required GitHub administrator action

Once this workflow produces passing PR checks, add required status checks
**by exact job name**: `policy / licenses and sources`,
`qml / static analysis`, and all seven named matrix `... / compile and test`
checks, or use an approved ruleset with equivalent enforcement. Use the actual
check names displayed by GitHub. Enable required checks only after their first
successful run. Do not claim branch protection is configured from files alone.
Review workflow changes with particular care because malicious PR code can
modify CI instructions. Maintainer self-review is not independent review.

## Outstanding gates

- Hosted GitHub Actions execution: **NOT VERIFIED**.
- Official `reuse lint` against final PR source: **NOT VERIFIED** here.
- `knetsentry_qmllint` on GitHub's Qt/KF6 versions: **NOT VERIFIED**.
- Full clang-format/qmlformat baseline and enforceable style policy: **NOT
  IMPLEMENTED**; whitespace/newline formatting hygiene is implemented.
- Artifact signing, SBOM, package rights, and full security qualification:
  deferred to later approved milestones.

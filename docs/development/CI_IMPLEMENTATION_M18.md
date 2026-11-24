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

## M1.8 follow-up — official REUSE parsing of verifier fixtures

The first M1.8 local `reuse lint` execution reported 12 Python tools as
missing licensing information. Those files already carried valid, unchanged
MIT copyright/license headers. REUSE also searched their assertion source
and interpreted extra literal license-tag examples as malformed SPDX license
expressions. For example, a Python expression testing a document header
was mistaken for another declaration **inside the Python tool itself**.

This corrective change replaces only the hyphen in **embedded Python string
literals** with the equivalent Python escape `\x2d`. When Python evaluates
the literals, the resulting string is byte-for-byte the same as before.
The actual leading SPDX headers remain in their normal, human-readable form;
no licensing assignment, redistribution declaration, test assertion, or
production source was changed. An additional M0.4 verifier literal beyond
the set reported by the installed tool was updated proactively to prevent
future full-file scanners from encountering the same false positive.

`python3 scripts/verify_m18_ci.py --format` now rejects additional literal
SPDX-license markers outside the real script headers. This is a defensive
source check **not a replacement for the official tool**. M0.6 and all later
policy verifiers must continue passing to demonstrate that their effective
license checks have not changed. The CI `policy` job still runs unmodified
`reuse lint` and must fail if REUSE reports any remaining issue.

### Acceptance for the follow-up

1. Run `reuse lint` on a clean checkout of this exact PR revision; require
   successful exit status and the positive compliance summary.
2. Run every `scripts/verify_m*.py` script and the M1.8 formatting hygiene
   command; verify all pass.
3. Run the Release and sanitizer CTest presets; ensure original test counts
   (13 and 10) and their security negative controls are unchanged.
4. Confirm the GitHub-hosted `policy`, seven matrix lanes, and `qml` job pass
   on the corrective commit before merge.

This local source-level correction was prepared without a working `reuse`
installation in the build environment. Therefore **official REUSE compliance
is not claimed until the user's Ubuntu host or GitHub Actions policy job
executes the tool successfully**.

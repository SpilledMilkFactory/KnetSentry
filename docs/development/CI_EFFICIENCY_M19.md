<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M1.9 — CI dependency provisioning efficiency

> Historical baseline and design contract. For current implemented behavior and
> acceptance evidence, see [project status](../PROJECT_STATUS.md). Future requirements
> and original milestone-specific test counts below are not release claims.

**Scope:** Optimize Ubuntu 26.04 GitHub Actions dependency provisioning;
preserve all nine existing required checks and all seven CMake/CTest presets.
This is **not** a GitHub Actions execution report or benchmark claim.

## Measured problem and first improvement

M1.8's `build` matrix previously used the same unconditional `apt-get update`
and entire Qt/Kirigami/Clazy/clang-tidy/OpenMP install list in **every** lane.
In particular, `linux-core-only` and `linux-sanitize-core-only` explicitly
have `KNETSENTRY_BUILD_DESKTOP=OFF`; installing Qt and KDE packages there
provided no test coverage and could incur large APT downloads. The
`policy` and `qml` jobs also installed their packages unconditionally.

M1.9 replaces those unconditional installs with
`scripts/ci/install_dependencies.sh <profile>`:

| Profile | Explicit direct packages | Why |
| --- | ---: | --- |
| `linux-core-only`, `linux-sanitize-core-only` | 4 | GCC/build tools, CMake, Ninja, Python; **no Qt, KDE, Clazy or clang-tidy** |
| `linux-release`, `linux-debug`, `linux-sanitize`, `qml` | 13 | Baseline build tools and Qt/Kirigami QML requirements |
| `linux-analysis` | 14 | Desktop plus clang-tidy |
| `linux-clazy` | 15 | Desktop plus Clazy and libomp-dev |
| `policy` | 3 | Python, PyYAML, official REUSE |

The helper performs package-presence checks using the local dpkg database,
logs missing direct packages, and runs `apt-get update` and a targeted install
**only if** packages are missing. If all direct packages are already
installed, there is no APT network request. The Ubuntu 26.04 x86-64 identity
check is retained; `--list` is available without changing system state.

`--list` can be reviewed offline:

```bash
bash scripts/ci/install_dependencies.sh linux-core-only --list
bash scripts/ci/install_dependencies.sh linux-clazy --list
bash scripts/ci/install_dependencies.sh policy --list
```

M4.2 adds one direct package (`libssl-dev`) to each build/QML profile;
policy remains unchanged. Exact OpenSSL package versions are logged. See
[identity dependency review](IDENTITY_M42.md). The table above is historical.

The per-run APT package list remains **unlocked** and reflects Ubuntu's
configured repositories. Package presence is not a supply-chain attestation;
normal dependency review and the existing licensing policy still apply.

## Cache decision — security and resource stewardship

No `actions/cache`, root-owned `/var/lib/apt` persistence, shared build-tree
restore, or externally hosted prebuilt toolchain was added. GitHub-hosted jobs
run in fresh VMs; **software preinstalled on the selected runner image** can be
reused in that job, but packages downloaded in one CI job are not automatically
available to the others or a future run. Skipping unnecessary installation is
the first optimization and has no new shared-cache trust boundary.

GitHub documents cache-poisoning and cross-trust restoration risks, especially
for untrusted PR workflows. If execution logs demonstrate substantial
**compilation** time after this fix, consider a separately reviewed,
cache-keyed compiler object cache (e.g. ccache) with no uploaded private logs,
strict cache trust boundaries, and an explicit invalidation strategy. Do not
cache mutable Qt/Kirigami runtime libraries or treat restored artifacts as
security evidence. Require an improvement measured against an uncached hosted
baseline before enabling persistence.

Reference: [GitHub Actions dependency caching](https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching).

## Qualification and limits

- Run `python3 scripts/verify_m19_contributors.py` and
  `python3 scripts/verify_m18_ci.py --format`.
- Run all available source-verifier scripts, official `reuse lint`, and local
  Release/sanitizer CTest suites.
- Hosted M1.9 acceptance requires all **nine GitHub Actions checks** to pass.
- Compare runner timing of the `Install only required Ubuntu 26.04 dependencies`
  step against the prior `Check runner and install Ubuntu 26.04 dependencies`
  step for the core-only lane. This is **not measured** until new hosted logs
  are available.
- New runner images, APT policy changes, and dependencies may still require
  package downloads and full rebuilds. This optimization never skips tests.

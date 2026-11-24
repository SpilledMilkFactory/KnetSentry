<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Contributor quickstart — Ubuntu 26.04 AMD64

**Supported development target:** Ubuntu 26.04 x86-64, with C++23, Qt 6,
KDE Frameworks 6/Kirigami, CMake and Ninja. A GNOME session is supported;
KDE Plasma is **not** required. This is a developer build of a **non-operational
SIEM shell**; no LAN capture, manager, agent, or production service exists.

## 1. Prepare a clean developer workstation

Use Ubuntu's standard package repositories and install the actual desktop,
Qt Test, and analysis dependencies (no vendored runtime or containers):

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build python3 \
  qt6-base-dev qt6-declarative-dev qt6-declarative-dev-tools \
  extra-cmake-modules libkirigami-dev \
  qml6-module-org-kde-kirigami qml6-module-qtquick \
  qml6-module-qtquick-controls qml6-module-qtquick-layouts \
  clazy libomp-dev clang-tidy reuse
```

For application development the distro-installed dependencies are sufficient.
You can also display the current **CI package profiles without installing**:

```bash
bash scripts/ci/install_dependencies.sh linux-release --list
bash scripts/ci/install_dependencies.sh linux-core-only --list
```

The profile helper's installation mode is for fresh GitHub runners and guards
its OS/architecture. Do not run it with `sudo` on a workstation; use the
explicit APT command above when local setup is needed. The CI runner provides
its own fresh VM and is not your personal machine.

## 2. Clone, configure, build, and test

```bash
git clone https://github.com/SpilledMilkFactory/KnetSentry.git
cd KnetSentry
cmake --preset linux-release --fresh
cmake --build --preset linux-release --parallel 2
ctest --preset linux-release --output-on-failure
```

The Release desktop suite currently contains **15 CTest tests**, including
real Qt Test, QML startup, navigation, diagnostics and binary-hardening checks.
Do not claim qualification on a failing command or because CTest merely lists
names. Run a version-independent command for the actual Qt Test subset:

```bash
ctest --test-dir build/presets/linux-release --output-on-failure -L qt
python3 scripts/verify_m17_suites.py --build-dir build/presets/linux-release
```

The inventory verifier checks that test executables exist; `ctest` determines
whether they pass.

## 3. Run the graphical application (unprivileged)

```bash
./build/presets/linux-release/apps/desktop/knetsentry --version
./build/presets/linux-release/apps/desktop/knetsentry
```

Use the Kirigami drawer or `Ctrl+1` through `Ctrl+7` to visit Dashboard,
Assets, Events, Detections, Alerts, Investigations, and Settings. The design
samples and status cards are **not collected telemetry**. No need for root,
packet capture, live LAN devices, or an Internet connection at runtime.

## 4. Security regression and policy checks

```bash
cmake --preset linux-sanitize --fresh
cmake --build --preset linux-sanitize --parallel 2
ctest --preset linux-sanitize --output-on-failure
python3 scripts/verify_m12_hardening.py --build-dir build/presets/linux-release
python3 scripts/verify_m17_suites.py --build-dir build/presets/linux-sanitize
python3 scripts/verify_m18_ci.py --format
for verifier in scripts/verify_m*.py; do python3 "$verifier" || exit 1; done
reuse lint
git diff --check
```

The full sanitizer suite currently contains **12 CTests**, including the
first-party deliberate-leak negative control. Source-only verifiers are not
proof of executable results; official REUSE lint is the licensing gate. The
CI workflow additionally runs Debug, Clazy, clang-tidy, and separate QML lint.
See [test-suite foundation](TEST_SUITE_FOUNDATION.md) and
[CI implementation](CI_IMPLEMENTATION_M18.md).

When working without Qt/KDE dependencies, use `linux-core-only` for a limited
C++ test (currently **7 CTests**) and `linux-sanitize-core-only` for **8**.
A core-only PASS **never** qualifies the desktop, network-monitoring, or
release security requirements.

## 5. Contributing safely

Branch from `main`; reference the relevant GitHub issue and milestone. Use
[CONTRIBUTING](../../CONTRIBUTING.md) and the existing
[PR template](../../.github/pull_request_template.md). Identify affected
trust boundaries, expected behavior, actual test commands/results, license and
dependency changes, unresolved risks, and self-review status. Before sharing
terminal output, **remove real LAN topology, IP addresses, credentials, paths,
private telemetry, exploit details, and other sensitive evidence**. The
application's structured diagnostics do not sanitize third-party Qt output.

For vulnerability reports, **do not create a public issue**; follow
[SECURITY.md](../../SECURITY.md) and GitHub's private advisory workflow.
Security testing must be limited to systems and networks you control or are
authorized to assess. Do not add agentless scanning or packet capture as part
of a documentation/test change.

## 6. Troubleshooting and evidence

- Missing Qt/Kirigami imports: verify the listed `qml6-module-*` packages;
  a successful CMake configure alone is insufficient.
- Clazy cannot find OpenMP: verify `libomp-dev`, and keep the Clazy preset.
- GUI fails offscreen: record the exact `ctest --output-on-failure` result and
  local Qt/ECM versions; do not disable mandatory tests.
- REUSE complains: fix the actual source SPDX tags or fixture text; don't
  skip the official lint gate.
- New CTest listed but not found: build the **same preset** before invoking
  `verify_m17_suites.py`. Do not equate registration with executable success.
- Public PR evidence: report `PASS`, `FAIL`, `BLOCKED`, `PLANNED`, or
  `NOT_APPLICABLE` honestly as the [evidence guide](VERIFICATION_EVIDENCE.md)
  requires. Reproductions should use sanitized synthetic input only.

The repository's future KDE adoption is an aspiration; it is not an official
KDE project, and no binary redistribution has been cleared by this guide.

## M2.1 — Local management daemon (non-operational)

The independent unprivileged foreground process builds with *every* preset,
including core-only. See [M2.1 daemon guide](MANAGER_DAEMON_M21.md).

```bash
./build/presets/linux-release/apps/manager/knetsentryd --help
./build/presets/linux-release/apps/manager/knetsentryd
# Stop with Ctrl+C (or SIGTERM from another terminal). Do not run as root.
```

No network listeners, IPC, telemetry, persistent audit logs, or GUI integration
are active. Two new CTests exercise real SIGTERM/SIGINT shutdown.


### M2.2 configuration verification

The Qt-independent manager accepts an optional, secure, versioned lifecycle
configuration file. See [M2.2 manager configuration](MANAGER_CONFIGURATION_M22.md).
Run `python3 scripts/verify_m22_configuration.py` and the compiled CTests;
never interpret a source-only PASS as runtime proof.

### M2.3 local IPC verification

`python3 scripts/verify_m23_ipc.py --build-dir build/presets/linux-release`
executes the real Unix-domain transport and negative authorization tests.
See [M2.3 IPC](LOCAL_AUTHENTICATED_IPC_M23.md).

### M2.4 service health verification

Run `python3 scripts/verify_m24_health.py --build-dir build/presets/linux-release`
after the applicable build and CTest. See [health contract](SERVICE_HEALTH_M24.md)
for the authenticated HEALTH exchange and units. The expected CTest inventory
is 21/18 desktop (normal/sanitized), 13/14 core-only (normal/sanitized).

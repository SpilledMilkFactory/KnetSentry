<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Contributor quickstart — Ubuntu 26.04 AMD64

**Supported development target:** Ubuntu 26.04 x86-64, with C++23, Qt 6,
KDE Frameworks 6/Kirigami, CMake and Ninja. A GNOME session is supported;
KDE Plasma is **not** required. This is a developer build of a **non-operational
SIEM shell** with a lifecycle-only manager and read-only scope inspection; no
operational capture, agent transport or manager-side event processing exists.
M5.2 adds explicitly selected local journal metadata in a bounded development store.

## 1. Prepare a clean developer workstation

Use Ubuntu's standard package repositories and install the actual desktop,
Qt Test, and analysis dependencies (no vendored runtime or containers):

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build python3 libssl-dev pkg-config libsystemd-dev \
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

The Release desktop suite currently contains **53 CTest tests**, including
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

The full sanitizer suite currently contains **48 CTests**, including the
first-party deliberate-leak negative control. Source-only verifiers are not
proof of executable results; official REUSE lint is the licensing gate. The
CI workflow additionally runs Debug, Clazy, clang-tidy, and separate QML lint.
See [test-suite foundation](TEST_SUITE_FOUNDATION.md) and
[CI implementation](CI_IMPLEMENTATION_M18.md).

When working without Qt/KDE dependencies, use `linux-core-only` for a limited
C++ test (currently **41 CTests**) and `linux-sanitize-core-only` for **42**.
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

## Milestone-specific reference (M2–M3)

The following sections describe incremental implementation contracts. For
current capabilities and accepted verification see [project status](../PROJECT_STATUS.md).

### M2.1 — Local management daemon (non-operational)

The independent unprivileged foreground process builds with *every* preset,
including core-only. See [M2.1 daemon guide](MANAGER_DAEMON_M21.md).

```bash
./build/presets/linux-release/apps/manager/knetsentryd --help
./build/presets/linux-release/apps/manager/knetsentryd
# Stop with Ctrl+C (or SIGTERM from another terminal). Do not run as root.
```

At M2.1 there were no IPC, audit or GUI integrations. The current manager
supports the opt-in local features documented below; operational IP transport
and telemetry remain disabled. The lifecycle tests exercise SIGTERM/SIGINT.


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

### M2.5 service audit verification

Run `python3 scripts/verify_m25_audit.py --build-dir build/presets/linux-release`
after CTest. Keep local audit records out of public artifacts.
See [audit contract](SERVICE_AUDIT_M25.md).

### M2.6 desktop health verification

Run `python3 scripts/verify_m26_desktop_health.py` for source policy and
`python3 scripts/verify_m26_desktop_health.py --build-dir build/presets/linux-release`
after building. The native client is tested in core-only builds too; only the
real desktop configuration qualifies Qt model and QML behavior. See
[desktop health](DESKTOP_HEALTH_M26.md) for manual start/stop/reconnect checks.

### M2.7 systemd service verification

See [systemd service integration](SYSTEMD_SERVICE_M27.md) for explicit
administrator installation and runtime acceptance on a systemd-booted host.
Normal builds and CI never install or activate the service. The source policy
CTest runs in all presets; live confinement must be separately verified.

### M2.8 service lifecycle and IPC integration

Run the full configured CTest suite or execute the focused regression:

```sh
ctest --preset linux-release -R '^knetsentry_service_lifecycle_ipc_integration$' --verbose --no-tests=error
```

See [service lifecycle and IPC integration](SERVICE_LIFECYCLE_IPC_M28.md) for
scenario coverage, conditional distinct-identity evidence, and limits.
The foreground test uses private temporary directories and never installs,
starts, stops or modifies an installed systemd service.

### M2.9 desktop toolbar

See [M2.9 toolbar contract](DESKTOP_DAEMON_TOOLBAR_M29.md). The existing explicit
IPC endpoint remains read-only; desktop-owned foreground lifecycle is separate.
The new desktop CTests are `knetsentry_qt_daemon_control` (including sanitizer)
and `knetsentry_gui_daemon_toolbar` (non-sanitized). Core-only counts are unchanged.

### M3.1 network scope policy

The mandatory `knetsentry_network_scope_policy` test runs in all seven presets.
Expected inventories: desktop 32/27 (normal/sanitized), core-only 20/21
(normal/sanitized). Run `python3 scripts/verify_m31_network_scope.py --build-dir
build/presets/linux-release` for focused evidence. See the
[M3.1 policy contract](NETWORK_SCOPE_POLICY_M31.md). No real IP network I/O is
performed by this test; live topology and enforcement remain unqualified.

### M3.2 dual-stack scope validation

The mandatory `knetsentry_network_prefix_validation` test runs in all seven
presets alongside the original M3.1 policy test. Current expected inventories:
desktop 33/28 (normal/sanitized), core-only 21/22 (normal/sanitized).
Run `python3 scripts/verify_m32_network_prefix.py --build-dir
build/presets/linux-release` for configured verification. See the
[M3.2 validation contract](NETWORK_SCOPE_VALIDATION_M32.md). No real IP network
I/O or new permissions are introduced.

### M3.3 Linux interface and route awareness

The mandatory `knetsentry_network_topology_awareness` test runs in all seven
presets. M3.3 inventories: desktop 34/29 (normal/sanitized),
core-only 22/23 (normal/sanitized). Run `python3
scripts/verify_m33_network_topology.py --build-dir build/presets/linux-release`
for configured verification. The optional isolated namespace regression and
its prerequisites are documented in the [M3.3 topology contract](NETWORK_TOPOLOGY_M33.md).
A recognized pre-entry namespace permission denial is BLOCKED (exit 77),
not a successful mutation test; an entered fixture failure remains FAIL.
Keep host security restrictions intact and use an approved test environment.
No real IP network transport is enabled.

### M3.4 Fail-closed network authorization

The mandatory `knetsentry_network_fail_closed_authorization` regression runs
in all seven presets. M3.4 inventories: desktop 35/30
(normal/sanitized), core-only 23/24 (normal/sanitized). Run `python3
scripts/verify_m34_network_authorization.py --build-dir build/presets/linux-release`
for configured verification. See the [M3.4 authorization contract](NETWORK_AUTHORIZATION_M34.md).
The optional M3.3 namespace watcher also checks the new gate's invalidation;
standard acceptance needs no namespace creation or host security changes.

### M3.5 Lifecycle-only nftables firewall

The mandatory `knetsentry_firewall_profile_contract` runs in all seven presets
and the policy job runs `python3 -B scripts/verify_m35_firewall.py`. Current
inventories: desktop 36/31 (normal/sanitized), core-only 24/25. Source fixtures
never invoke nft or require administrator privileges. The separate explicitly
requested `sudo /usr/bin/python3 -I -B scripts/firewall_m35.py live-isolated`
requires the dedicated account, nftables, iproute2, IPv6 and a fresh privileged
network namespace. It must pass before claiming kernel firewall qualification;
no host rule installation is performed by it. See the
[M3.5 firewall contract](FIREWALL_ENFORCEMENT_M35.md) for deployment and rollback.

### M3.6 Isolated network policy fixtures

`knetsentry_network_isolation_fixture` is mandatory in all seven presets.
M3.6 inventories: desktop 37/32 (normal/sanitized), core-only 25/26.
`python3 -B scripts/verify_m36_network_fixture.py` checks the offline fixture
contract. Explicit live qualification uses `sudo /usr/bin/python3 -I -B
scripts/network_fixture_m36.py --binary
build/presets/linux-release/tests/knetsentry_network_isolation_test`.
The local runner flag is `--network-fixture`; retain `--firewall-namespace` to
repeat M3.5. No external service or host firewall mutation is required. See the
[M3.6 fixture contract](NETWORK_ISOLATION_FIXTURES_M36.md) for prerequisites,
limits and cleanup. A failed or unexecuted live test is not enforcement evidence.

### M3.7 Adversarial network-boundary qualification

`knetsentry_network_adversarial_boundary` is mandatory in all seven presets.
M3.7 inventories: desktop 38/33 (normal/sanitized), core-only 26/27.
Run `python3 -B scripts/verify_m37_adversarial.py` for offline fixture checks.
The existing explicit M3.6 live command now includes M3.7 packet and topology
regressions; see [M3.7 qualification](NETWORK_ADVERSARIAL_M37.md).

### M3.8 Desktop LAN scope inspection

See [M3.8 desktop scope contract](DESKTOP_NETWORK_SCOPE_M38.md). Test inventories
remain desktop 38/33 (normal/sanitized), core-only 26/27. The existing health
model, owned-daemon lifecycle, navigation and live GUI health regressions now
cover scope inspection. Run `python3 -B scripts/verify_m38_desktop_scope.py`
for the source contract, or add `--build-dir build/presets/linux-release` for
configured model/navigation checks. The live GUI health regression also verifies
Settings updates and the distinction between local IPC rejections and network
denials. The existing strict QML and live network acceptance checks remain required.

## M4.1 agent wire contract

See [KSAP 1.0](AGENT_PROTOCOL_M41.md). The offline protocol regression runs in
all seven presets; M4.1 desktop inventories were 39/34 and core-only 27/28
(normal/sanitized). No operational agent network traffic is introduced.

## M4.2 identity foundation

Install the system OpenSSL 3.5.x development package (`libssl-dev`). All
seven presets execute `knetsentry_identity_contract`; M4.2 desktop counts
were 40/35 and core-only 28/29 (normal/sanitized). No real keys, deployment,
privileges or network access are needed for this regression. See the
[M4.2 identity contract](IDENTITY_M42.md).

## M4.3 mutual TLS

The existing OpenSSL development package supplies both shared libraries. All
seven presets run `knetsentry_tls_contract`; desktop counts are 41/36 and
core-only 29/30 (normal/sanitized). See [transport contract](TLS_TRANSPORT_M43.md).

## M4.4 explicit enrollment

Both `knetsentry_enrollment_contract` and `knetsentry_enrollment_admin` are
mandatory in all seven presets. Desktop inventories: 43/38, core-only 31/32
(normal/sanitized). See [explicit enrollment](ENDPOINT_ENROLLMENT_M44.md).
No additional package, real endpoint, or privileged operation is needed.

## M4.5 credential lifecycle

`knetsentry_credential_lifecycle` is mandatory in all seven presets. Desktop
inventories: 44/39, core-only 32/33 (normal/sanitized). The enrollment CLI
regression also exercises rotation and revocation. See the
[credential lifecycle contract](CREDENTIAL_LIFECYCLE_M45.md).

## M4.6 agent heartbeat and health

`knetsentry_agent_health_contract` is mandatory in all seven presets. Desktop
inventories: 45/40, core-only 33/34 (normal/sanitized). See the
[agent health contract](AGENT_HEALTH_M46.md). No new dependencies or privileges.

## M4.7 desktop enrollment roster

Mandatory codec and real-manager roster tests run in all seven presets.
Current inventories: desktop 47/42, core-only 35/36 (normal/sanitized).
See [desktop enrollment management](DESKTOP_AGENT_MANAGEMENT_M47.md).

## M4.8 authentication and transport security regressions

Run `knetsentry_authentication_transport_regression` in all seven presets.
See the [M4.8 regression contract](AUTHENTICATION_TRANSPORT_REGRESSIONS_M48.md).

## M5.1 endpoint-agent service

The independent agent and its two mandatory lifecycle/process tests are built
in all seven presets (50/45 desktop and 38/39 core-only, normal/sanitized).
See [M5.1 agent startup and privilege policy](ENDPOINT_AGENT_SERVICE_M51.md).

## M5.2 systemd journal collection

Install `libsystemd-dev` and `pkg-config` from the distro. Keep journal collection
explicitly opt-in and run as an ordinary user; never elevate to read additional
logs. See [M5.2 journal collection](JOURNAL_COLLECTION_M52.md) for the private
state directory, bounded cursor and separate live-source qualification.

## M5.3 authentication and SSH collection

Use the explicit authentication mode and separate protected local state described
in [M5.3](AUTHENTICATION_COLLECTION_M53.md). Mandatory tests use synthetic data.

## M5.4 Linux Audit integration

Use the explicit audit mode in [M5.4](AUDIT_COLLECTION_M54.md) with a separate
private directory. Empty selection is unknown visibility; never grant privileges
for qualification. The mandatory regression uses synthetic native records.

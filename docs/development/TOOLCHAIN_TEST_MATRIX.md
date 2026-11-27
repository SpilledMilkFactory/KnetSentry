<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Toolchain, Build Presets and Test Strategy

**State:** M6.4 SQLite accepted; M6.5 integrity qualification pending; issues #40/#46/#50/#51 remaining capabilities open; Ubuntu 26.04 AMD64.
Seven mandatory build/test presets and nine hosted CI checks are active. Current
CTest inventories are 65 Release/Debug/Clazy/analysis, 59 full ASan/UBSan,
52 core-only and 53 sanitized core-only. See [project status](../PROJECT_STATUS.md) for recorded
acceptance and the [build guide](BUILD_FOUNDATION.md). Historical milestone
sections below describe earlier inventories, not today's totals.

## Planned build and analysis matrix

| Gate | Proposed mechanism | Owner | Preconditions and limits |
| --- | --- | --- | --- |
| Build | GCC C++23, CMake + Ninja, compiler warning flags | M1.1/M1.2 | Pin actual compiler and CMake minimum after local check; do not assume a GitHub runner image version |
| Release | `linux-release` configure/build/test presets | M1.1/M1.2 | First-party warnings-as-errors and ELF hardening active; final packaging inspection remains M15 |
| Sanitizer | `linux-sanitize` ASan + UBSan with symbols | M1.2/M1.7 | Presets qualified for M3.8 on Ubuntu 26.04; dynamic third-party libraries may not be instrumented |
| Static C++ | opt-in `linux-analysis` clang-tidy | M1.2/M1.8 | Preset configured; mandatory CI checks active |
| Static Qt C++ | opt-in `linux-clazy` compiler preset | M1.2/M1.8 | Requires installed Clazy; CI integration active |
| QML | `qmllint` and `qmlformat` | M1.8 | Require module import paths; validate available versions |
| C++/Qt unit | CTest and Qt Test | M1.7 | Synthetic deterministic fixtures, unique test IDs |
| GUI interaction | Qt Quick Test and offscreen smoke tests | M1.7/M8.9 | Headless result is not KDE Plasma/GNOME human acceptance |
| Integration | Unix IPC, agent TLS, daemon restart | M2–M7 | Isolated loopback/namespaces, unauthorized peer cases |
| Network | nftables, route/interface, capture | M3.6/M5.10/M13.5 | Isolated disposable network namespaces; never alter default host firewall during PR tests |
| Storage | raw-first, mount loss, SQLite recovery | M6.9/M14.4 | Synthetic filesystems and explicit mount IDs, no home-telemetry fixtures |
| Fuzzing | bounded parser/rule/IPC fuzz targets and seed corpora | M13.2/M13.3 | Use supported Clang/libFuzzer or other reviewed engine; deterministic regression corpus always runs |
| Packaging | installed artifacts, ELF hardening, dependencies, licensing | M15.5/M15.7 | Test exact produced artifacts on fresh supported environments |
| Performance | M0.5 W-00..W-09 workloads | M14 | Record packet/s and normalized event/s separately; report drops and limitations |

## Compiler and runtime hardening

Evaluate flags on actual Ubuntu 26.04 toolchains, not blindly on every
library: high-signal warning families, `-Werror` on project-owned targets,
`-fstack-protector-strong`, appropriate `_FORTIFY_SOURCE` levels, PIE/PIC,
linker RELRO and `-z now` where applicable. Verify the final ELF properties
and effective process privileges; a flag in CMake is not proof of hardening.
Debug/sanitizer and production flags serve different purposes. Avoid running
ASan-instrumented tests against production secrets or normal capture
interfaces. AddressSanitizer and ThreadSanitizer cannot simply be combined;
TSan or other concurrency tooling should be a separately verified job.

## Test-label taxonomy and coverage rules

Use stable CTest labels such as `unit`, `integration`, `security`, `qml`,
`regression`, `fuzz-smoke`, `performance`, and `requires-isolation`. Labels
must not replace executing required tests. A PR check must fail if required
new tests are missing or if CTest unexpectedly discovers zero tests. Qt GUI
smoke tests must verify exit status and absence of QML load errors, not just
that a window appeared. Performance tests should be run on dedicated or
recorded hardware and not cause flaky PR failures due to unknown runners.

## Example commands after M1 activation

```bash
cmake --preset linux-release
cmake --build --preset linux-release --parallel
ctest --preset linux-release --output-on-failure
cmake --preset linux-sanitize
cmake --build --preset linux-sanitize --parallel
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ctest --preset linux-sanitize --output-on-failure
```

The `linux-release` configure/build/test commands are now usable after
installing Qt/KDE build dependencies on Ubuntu 26.04. The `linux-sanitize` preset is implemented by M1.2; run and verify the
full desktop on Ubuntu 26.04 before accepting that gate.
See [verification cases](VERIFICATION_MATRIX.md) for activation and evidence.

## Authoritative reference links

- [CMakePresets manual](https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html)
- [Qt 6 CMake integration](https://doc.qt.io/qt-6/cmake-manual.html)
- [Qt Test](https://doc.qt.io/qt-6/qttest-index.html)
- [Qt Quick Test](https://doc.qt.io/qt-6/qtquicktest-index.html)
- [qmllint](https://doc.qt.io/qt-6/qtqml-tooling-qmllint.html)
- [KDE Clazy](https://github.com/KDE/clazy)
- [GCC instrumentation options](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)

See the [M1.2 hardening guide](HARDENING_AND_ANALYSIS.md) for current commands, flags, and evidence requirements.


## M1.7 executable test foundation

M1.7 adds a compiled Qt-independent diagnostic boundary test, a production
read-only section catalog with Qt Test model-contract coverage, Qt Test
application initialization via actual desktop QProcess, and a configured
CTest inventory gate. Full desktop builds **require** Qt6::Test; a missing
package is a configuration failure, not a skipped test. Expected inventories:
M1.7 historical totals were Release/Debug/Clazy/analysis 13; sanitizer 10;
core-only 5; sanitized core-only 6. M2.1 adds two manager tests to every
configuration: desktop 15, sanitizer 12, core-only 7, sanitized core-only 8. See [M1.7 test-suite contract](TEST_SUITE_FOUNDATION.md).
All counts are targets until CTest has run on the intended revision.

## M1.8 hosted CI implementation

The [Ubuntu 26.04 workflow](../../.github/workflows/ubuntu-26-04.yml) covers the seven accepted M1.7 presets, source policy verification and Qt-generated QML lint. The maintainer reported nine passing M1.8 hosted checks; see the current status for later evidence. See [CI implementation details](CI_IMPLEMENTATION_M18.md).

## M2.1 manager lifecycle verification

The independent `knetsentryd` executable and explicit state machine are built
with every configuration, including core-only. `knetsentry_manager_state_contract`
rejects illegal transitions; `knetsentry_manager_signal_lifecycle` launches
a real non-root process and verifies SIGTERM/SIGINT, fixed JSON diagnostics,
unsupported arguments and root rejection. See [manager lifecycle](MANAGER_DAEMON_M21.md).

## M2.2 manager configuration tests

`knetsentry_manager_configuration_contract` and
`knetsentry_manager_configuration_runtime` verify strict schema v1 parsing,
unsafe-file rejection, no-fallback behavior and clean configured shutdown.
New expected counts: desktop Release/Debug/Clazy/analysis **17**, full
sanitizer **14**, core-only **9**, core-only sanitizer **10**.
See [manager configuration](MANAGER_CONFIGURATION_M22.md).

### M2.3 local IPC qualification

M2.3 registers `knetsentry_local_ipc_authorization_contract` and
`knetsentry_local_ipc_runtime` across all configurations. Expected counts:
19 Release/Debug/Clazy/analysis; 16 full ASan/UBSan; 11 core-only Release;
12 core-only sanitizer. All nine CI jobs are unchanged. Source-only checks
are not proof of actual peer-credential enforcement; use compiled tests and
Linux runtime negative tests. The read-only `TB-05` subset must not be
represented as a completed management authorization implementation.

### M2.4 service health qualification

`knetsentry_service_health_contract` and `knetsentry_service_health_runtime`
are mandatory across all seven presets. Expected counts: 21 desktop
Release/Debug/Clazy/analysis; 18 full ASan/UBSan; 13 core-only Release;
14 core-only sanitizer. See [health contract](SERVICE_HEALTH_M24.md).
The nine hosted checks are unchanged; actual execution remains required.

### M2.5 service audit verification

Mandatory `knetsentry_service_audit_contract` and `knetsentry_service_audit_runtime`
run across all seven presets. Expected 23/20 desktop (normal/sanitized),
15/16 core-only (normal/sanitized).
See [audit contract](SERVICE_AUDIT_M25.md).

### M2.6 desktop health verification

Two new native client tests run across all seven presets. The Qt health model
contract runs in every desktop preset; live embedded QML with daemon stop and
restart runs in non-sanitized desktop configurations. Existing scoped QML LSan
suppressions remain unchanged. Expected desktop 27/23 (normal/sanitized),
core-only 17/18 (normal/sanitized). See [desktop health](DESKTOP_HEALTH_M26.md).

### M2.7 systemd service hardening

One mandatory source-policy regression CTest is added in every preset. Expected
counts: desktop 28/24 (normal/sanitized), core-only 18/19 (normal/sanitized).
Systemd parser and separate privileged installed-unit qualification are described
in [the service contract](SYSTEMD_SERVICE_M27.md); hosted source-only CI is not
proof of live isolation.

### M2.8 service lifecycle and IPC integration

One new mandatory real-process CTest runs in every preset, including both
sanitizer presets. Expected counts: desktop 29/25 (normal/sanitized),
core-only 19/20 (normal/sanitized). See
[the lifecycle integration contract](SERVICE_LIFECYCLE_IPC_M28.md).
The M2.7 live systemd gate and M2.6 actual QML lifecycle regression remain
separate; hosted CI does not claim installed-service qualification.

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

## M4.1 protocol contract

`knetsentry_agent_protocol_contract` is mandatory in all seven configurations,
including both sanitizer presets. See [KSAP 1.0](AGENT_PROTOCOL_M41.md) for
wire limits, error handling, ordering and transport prerequisites.

## M4.2 cryptographic identity contract

`knetsentry_identity_contract` is mandatory in all seven presets, including
both sanitizer builds. The offline regression generates ephemeral keys and
certificates using the system shared OpenSSL 3.5.x libcrypto. See the
[identity contract and dependency decision](IDENTITY_M42.md).

## M4.3 mutual TLS transport

`knetsentry_tls_contract` is mandatory across all seven presets, including
both sanitizers. The actual encrypted exchange and negative peer fixtures
need no network or credentials. Inventories: desktop 41/36, core-only 29/30
(normal/sanitized). See [transport contract](TLS_TRANSPORT_M43.md).

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

Mandatory codec and actual manager roster tests run in all seven presets.
Current inventories: desktop 47/42, core-only 35/36 (normal/sanitized).
The existing nonsanitized GUI runtime test verifies real roster bindings.
See [desktop enrollment management](DESKTOP_AGENT_MANAGEMENT_M47.md).

## M4.8 authentication and transport security regressions

All seven presets require `knetsentry_authentication_transport_regression`
(48/43 desktop, 36/37 core-only, normal/sanitized). See the
[M4.8 regression contract](AUTHENTICATION_TRANSPORT_REGRESSIONS_M48.md).

## M5.1 endpoint-agent service

Mandatory `knetsentry_agent_lifecycle_contract` and
`knetsentry_agent_service_runtime` in all seven configurations. Current
inventories: 50/45 desktop, 38/39 core-only (normal/sanitized). The agent
and its test executable receive standard hardening and instrumentation.
See [M5.1 service contract](ENDPOINT_AGENT_SERVICE_M51.md).

## M5.2 systemd journal collection

All seven build presets require distro `libsystemd-dev` and `pkg-config`.
The mandatory journal contract adds one CTest per preset, with isolated synthetic
records and empty/populated native journal directories. Local authorized live
journal verification remains distinct; see the
[M5.2 contract](JOURNAL_COLLECTION_M52.md).

## M5.3 authentication collection

One mandatory populated native authentication fixture CTest per preset. See
[M5.3 authentication contract](AUTHENTICATION_COLLECTION_M53.md).

## M5.4 Linux Audit integration

All seven presets require `knetsentry_audit_collection_contract`; see the
[M5.4 contract](AUDIT_COLLECTION_M54.md). Native fixture and unavailable-source
checks do not require host audit privileges.

## M5.5 secure telemetry buffering and delivery

All seven presets require `knetsentry_telemetry_delivery_contract`; see the
[M5.5 contract](TELEMETRY_DELIVERY_M55.md). Genuine encrypted in-memory TLS and
protected synthetic outbox/inbox are exercised without operational sockets.

## M5.6 initial file integrity monitoring

`knetsentry_file_integrity_contract` is mandatory in all seven presets. See
[M5.6](FILE_INTEGRITY_M56.md). Actual agent process, synthetic authorized file
changes and unsafe substitutions, no privileged host file access.

## M5.7 privacy and data minimization

All seven presets require `knetsentry_privacy_policy_contract`; see
[M5.7](PRIVACY_MINIMIZATION_M57.md). Actual-agent source/permit exclusions,
metadata-only file monitoring, slot redaction and policy-bound state rejection;
existing native authentication fixture verifies acquisition-time category
redaction and restart. No host private telemetry or new privileges.

## M5.8 collector verification and failure recovery

All seven presets require `knetsentry_collector_recovery_contract`; the
existing telemetry delivery regression also covers real sender and receiver
pending-file collision failures. See [M5.8](COLLECTOR_RECOVERY_M58.md).
Run the synthetic fault scenarios as an ordinary user. CTest timeout is 75
seconds. No production socket or power-loss qualification is claimed.

## M5.9 local endpoint telemetry status

See [M5.9](DESKTOP_TELEMETRY_STATUS_M59.md). Both status contract and actual
agent runtime tests are mandatory in all seven presets. Existing Qt model and
navigation tests exercise the read-only properties. Non-sanitized desktop
presets also run the actual rendered synthetic-pipe status test. No new QML
leak suppression or operational network access is introduced.

## M6.1 bounded authenticated event ingestion

See [M6.1](EVENT_INGESTION_M61.md). The mandatory ingestion contract runs in all seven presets using the existing enrollment test executable and project hardening policies. The existing delivery and recovery regressions traverse the new ingestion boundary.

## M6.2 pinned OCSF-aligned normalization

See [M6.2](EVENT_NORMALIZATION_M62.md). The standalone normalization contract is mandatory in all seven presets and uses existing project compiler, sanitizer and binary-hardening policies. Existing TLS ingestion and delivery regressions also verify typed-result gating and original provenance.

## M6.3 event storage abstraction

See [M6.3](EVENT_STORAGE_M63.md). The standalone storage contract is mandatory in all seven presets, with existing compiler, sanitizer and ELF hardening gates. It runs through the database-independent interface without a GUI, database, filesystem fixture, network or production credentials.

### M6.4 SQLite development backend

The [M6.4 regression](SQLITE_STORAGE_M64.md) is mandatory in all seven presets.
Distro SQLite >= 3.37 is required. Synthetic dedicated private fixtures exercise
restart, schema migration, transactional rollback, search, retention and mode
validation. Clang analyzer diagnostics are now fatal in the analysis preset;
no enum diagnostic is suppressed. The target inventory is 417 CTest executions.

### M6.5 evidence integrity

The [M6.5 regression](EVIDENCE_INTEGRITY_M65.md) is mandatory in all seven presets. It tests digest vectors, migration origin, restart, runtime tamper rejection and retention. Target: 424 CTest executions, 57 structural verifiers and 126 consolidated gates; official Ubuntu qualification pending.

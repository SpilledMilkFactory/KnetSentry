<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Toolchain, Build Presets and Test Strategy

**State:** M1.2 hardening and sanitizer/analysis presets, M1.3–M1.5 Qt/Kirigami
window/navigation/design, M1.6 diagnostics, M1.7 CTest/Qt Test suites and M1.8
Ubuntu 26.04 GitHub Actions CI exist. Nine M1.8 PR checks were reported green;
M1.9's CI dependency optimization is not yet qualified on hosted runners.
Initial supported target is Ubuntu 26.04 AMD64. See the
[M1.1 build guide](BUILD_FOUNDATION.md).

## Planned build and analysis matrix

| Gate | Proposed mechanism | Owner | Preconditions and limits |
| --- | --- | --- | --- |
| Build | GCC C++23, CMake + Ninja, compiler warning flags | M1.1/M1.2 | Pin actual compiler and CMake minimum after local check; do not assume a GitHub runner image version |
| Release | `linux-release` configure/build/test presets | M1.1/M1.2 | First-party warnings-as-errors and ELF hardening active; final packaging inspection remains M15 |
| Sanitizer | `linux-sanitize` ASan + UBSan with symbols | M1.2/M1.7 | Presets implemented; validate on Ubuntu 26.04; dynamic third-party libraries may not be instrumented |
| Static C++ | opt-in `linux-analysis` clang-tidy | M1.2/M1.8 | Preset configured; mandatory CI checks remain M1.8 |
| Static Qt C++ | opt-in `linux-clazy` compiler preset | M1.2/M1.8 | Requires installed Clazy; release CI integration remains M1.8 |
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

The [Ubuntu 26.04 workflow](../../.github/workflows/ubuntu-26-04.yml) covers the seven accepted M1.7 presets, source policy verification and Qt-generated QML lint. **Host-run evidence pending.** See [CI implementation details](CI_IMPLEMENTATION_M18.md).

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

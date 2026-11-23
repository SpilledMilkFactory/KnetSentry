<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Toolchain, Build Presets and Test Strategy

**State:** M0.7 contract; the CMake project, Qt tests and toolchain presets
are **not yet implemented**. Initial supported target is Ubuntu 26.04 AMD64.

## Planned build and analysis matrix

| Gate | Proposed mechanism | Owner | Preconditions and limits |
| --- | --- | --- | --- |
| Build | GCC C++23, CMake + Ninja, compiler warning flags | M1.1/M1.2 | Pin actual compiler and CMake minimum after local check; do not assume a GitHub runner image version |
| Release | `linux-release` configure/build/test presets | M1.1/M1.7 | Warnings-as-errors for first-party code after baseline stabilization |
| Sanitizer | `linux-sanitize` ASan + UBSan with symbols | M1.2/M1.7 | Test instrumented first-party code; dynamic third-party libraries may not be fully instrumented |
| Static C++ | clang-tidy on compilation database | M1.8 | Versioned checks; false-positive suppression needs review and expiry |
| Static Qt C++ | Clazy compatible with installed Clang/Qt | M1.8 | Only apply to Qt targets; do not assume available in every toolchain |
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

The preset names and environment are proposals, not usable commands in M0.7.
See [verification cases](VERIFICATION_MATRIX.md) for activation and evidence.

## Authoritative reference links

- [CMakePresets manual](https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html)
- [Qt 6 CMake integration](https://doc.qt.io/qt-6/cmake-manual.html)
- [Qt Test](https://doc.qt.io/qt-6/qttest-index.html)
- [Qt Quick Test](https://doc.qt.io/qt-6/qtquicktest-index.html)
- [qmllint](https://doc.qt.io/qt-6/qtqml-tooling-qmllint.html)
- [KDE Clazy](https://github.com/KDE/clazy)
- [GCC instrumentation options](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)

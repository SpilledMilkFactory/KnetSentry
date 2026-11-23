<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M1.2 — Compiler Hardening, Sanitizers and Analysis

**Scope:** GitHub issue #10; supported production target Ubuntu 26.04 LTS AMD64, GCC 15.2.0 observed on developer host. These controls harden **KnetSentry-owned C++ targets**, not installed Qt/KDE dependencies or unimplemented services.

## Build configurations and qualification

| Preset | Purpose | Claims and limits |
| --- | --- | --- |
| `linux-release` | Optimized C++ and Qt bootstrap with warnings-as-errors, fortify, stack protector, PIE, RELRO and immediate binding | Requires real Ubuntu desktop compile + CTest + ELF verification; no SIEM implemented |
| `linux-debug` | Debug C++ and Qt bootstrap with warnings-as-errors, without Release-only fortify/linker policy | Not a production-hardened binary |
| `linux-core-only` | Qt-free core smoke | Does not qualify desktop |
| `linux-sanitize` | Debug Qt bootstrap and core compiled with GCC/Clang ASan + UBSan | Detects some memory/UB defects in instrumented code; Qt/KDE system libraries not instrumented |
| `linux-sanitize-core-only` | Qt-free ASan + UBSan smoke | Does not qualify desktop |
| `linux-analysis` | Full desktop build with clang-tidy on first-party targets | Explicitly fails configuration when clang-tidy is absent; no QML tests yet |
| `linux-clazy` | Full desktop build using KDE Clazy compiler wrapper | Explicitly fails if `clazy` is unavailable; use separate compiler/build tree |

The hardening options are applied through `cmake/KnetSentryBuildOptions.cmake` **only** using `knetsentry_apply_project_options()` on first-party targets. Do not add global `-Werror`, `-fsanitize`, or linker flags to Qt, KDE, or vendored dependencies. On Linux/GCC or Clang, missing release-hardening capabilities produce a CMake configure error. Compiler/linker acceptance is a prerequisite; the `knetsentry_build_hardening` CTest and final artifact inspection are further evidence.

## Normal desktop and sanitizers

```bash
cmake --preset linux-release
cmake --build --preset linux-release --parallel
ctest --preset linux-release --output-on-failure
python3 scripts/verify_m12_hardening.py --build-dir build/presets/linux-release

cmake --preset linux-debug
cmake --build --preset linux-debug --parallel
ctest --preset linux-debug --output-on-failure

cmake --preset linux-sanitize
cmake --build --preset linux-sanitize --parallel
ctest --preset linux-sanitize --output-on-failure
python3 scripts/verify_m12_hardening.py --build-dir build/presets/linux-sanitize
```

The sanitizer CTest preset sets `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1` and `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. Run on **synthetic test data** without privileged capture or production telemetry. If sanitizers fail due to an environmental/runtime issue, preserve the failure and diagnose it; do not hide it behind `|| true` or globally disable leak checking. Never combine ASan with TSan in the same executable.

## Static C++ and Qt analysis (opt-in until CI policy activates it)

```bash
sudo apt install clang-tidy clazy
cmake --preset linux-analysis
cmake --build --preset linux-analysis --parallel
ctest --preset linux-analysis --output-on-failure

# Clazy uses clang as its compiler; a separate cache is mandatory:
cmake --preset linux-clazy
cmake --build --preset linux-clazy --parallel
ctest --preset linux-clazy --output-on-failure
```

The Clazy preset uses the upstream-supported `CMAKE_CXX_COMPILER=clazy` wrapper; `CLAZY_CHECKS=level0` may be set in the environment for explicitly selected checks. Diagnose any first-party warnings rather than silently suppressing them. `linux-analysis` requires `clang-tidy`; it is not a substitute for Clazy. Neither preset substitutes for M1.8 CI automation, M1.7 Qt Test, or future QML linting. A Clazy or clang-tidy failure is `FAIL`/`BLOCKED` until resolved.

### Clazy on Ubuntu 26.04: Clang OpenMP prerequisite

The `linux-clazy` preset makes `/usr/bin/clazy` (Clang, not GCC) the C++ compiler. Ubuntu's **installed** `KF6Kirigami` CMake package may require OpenMP as a dependency. OpenMP can be available to GCC via `libgomp` while remaining unavailable to Clang until the matching LLVM `libomp` development runtime is installed. In that case, the message `Could NOT find KF6 (missing: Kirigami)` is a *downstream symptom*, not proof that `libkirigami-dev` is absent.

For the documented Clazy/Clang **21** toolchain on Ubuntu 26.04 AMD64:

```bash
sudo apt update
sudo apt install libomp-21-dev

# Clear cached compiler/dependency probes from the failed configuration.
cmake --preset linux-clazy --fresh && \
cmake --build --preset linux-clazy --parallel && \
ctest --preset linux-clazy --output-on-failure
```

For another Clang major version, install its matching `libomp-<major>-dev` package as provided by the distribution. If the package is unavailable, investigate the actual compiler/runtime mismatch rather than forcing `KF6Kirigami_FOUND` or disabling the dependency. CMake now detects this condition early when using the Clazy compiler wrapper, with an actionable diagnostic. This does not introduce an OpenMP dependency into the KnetSentry core or the standard GCC presets. The Qt QML `qmlplugindump`/`org.kde.kirigami` warning is a **separate** M1.3 runtime-discovery issue and should be investigated after the GUI exists.

## Hardening evidence and limitations

- Project-owned targets use `-Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wconversion -Wsign-conversion -Wnull-dereference -Werror` on supported GNU/Clang toolchains.
- **Release** uses `-fstack-protector-strong`, `_FORTIFY_SOURCE=3`, position-independent executables, and linker `-z relro` and `-z now`. Debug and sanitizer builds do not claim those Release-only flags.
- The M1.2 offline verifier checks the resolved compilation database, Ninja link commands, and executable ELF properties (PIE, GNU_RELRO, NOW) if a build directory is supplied. An unbuilt source-only check cannot establish binary hardening.
- `_FORTIFY_SOURCE=3` covers eligible libc calls under appropriate optimization; it is not memory safety or proof against all overflows. ASan/UBSan coverage depends on instrumentation and test coverage. Compiler warning success does not eliminate vulnerabilities.
- M15 separately validates **the actual released binaries** and their packaged dependencies. Qt/KDE QML runtime checks, including the existing `qmlplugindump`/Kirigami module discovery warning, belong to M1.3 and must not be confused with a working graphical application.
- Any deliberate warnings-as-errors or hardening opt-out is for local diagnosis and cannot qualify Release acceptance. Record compiler, CMake, Qt/KF6, analyzer versions and any exceptions in the verification evidence.

## References

- [Development contract](../../DEVELOPMENT_CONTRACT.md)
- [M1.1 foundation](BUILD_FOUNDATION.md)
- [Toolchain and testing plan](TOOLCHAIN_TEST_MATRIX.md)
- [GCC instrumentation options](https://gcc.gnu.org/onlinedocs/gcc-15.2.0/gcc/Instrumentation-Options.html)
- [CMake linker flag checking](https://cmake.org/cmake/help/latest/module/CheckLinkerFlag.html)
- [KDE Clazy](https://github.com/KDE/clazy)

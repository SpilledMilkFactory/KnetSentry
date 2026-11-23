<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M1.1 — Build and Source Architecture

**Status:** M1.3 desktop foundation implemented; NOT a functioning SIEM.
**Scope:** GitHub issue #9; Ubuntu 26.04 LTS AMD64 is the supported build target.

## 1. Rationale and ownership

| Location / CMake target | Responsibility | Runtime dependencies | Future work |
| --- | --- | --- | --- |
| `src/core/` / `knetsentry_core` | Qt-free foundational library and immutable build identity | C++23 standard library | Shared core APIs and tests |
| `include/knetsentry/core/` | Public, namespaced core headers | C++23 standard library | Versioned service-neutral APIs |
| `apps/desktop/` / `knetsentry` | Real Qt Quick/Kirigami window; headless `--help`, `--version`, `--self-test-qml` | Qt6 Core/Gui/Qml/Quick/QuickControls2, Kirigami runtime | M1.4 navigation, M2+ services |
| `tests/` / `knetsentry_core_smoke` | Initial deterministic CTest smoke | Qt-free core | M1.7 Qt Test, Quick Test, full unit/integration suite |
| `apps/manager/`, `apps/agent/`, `apps/cli/` | **Reserved**, not yet implemented or generated | None yet | M2.1, M5.1, subsequent CLI issues |
| `src/security/`, `src/telemetry/`, `src/storage/` | **Reserved**, not yet implemented | None yet | Respective security milestones |

Do not add empty, misleading executables for services or sensors. The `knetsentry_core` static library is reusable without a Qt dependency. Avoid global include directories, globally enabled privileges, network access, downloaded build-time dependencies, or embedding private machine paths. The current project version `0.0.0` indicates an unreleased bootstrap—not a product release.

## 2. Ubuntu 26.04 AMD64 prerequisites

Enable the Ubuntu `universe` repository if it is not already enabled, then use distribution-supplied packages:

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build qt6-base-dev qt6-declarative-dev extra-cmake-modules libkirigami-dev
```

The full desktop requires **Qt6 Core/Gui/Qml/Quick/QuickControls2**, **ECM 6+**, and **KF6 Kirigami** at configure time. Ubuntu 26.04 also needs the `qml6-module-org-kde-kirigami` QML runtime package. The `knetsentry_kirigami_qml_startup` CTest actually instantiates `Kirigami.ApplicationWindow` and **fails** if the QML runtime or required imports are missing. The legacy ECM `qmlplugindump` check produced a false negative despite installed KF6 development packages; we replaced that metadata-only probe with the runtime test. A completed CMake configure alone does **not** qualify QML. No dependency is auto-downloaded or substituted. Verify local package versions with `apt-cache policy` and the configure output. Dependencies remain `CANDIDATE` / `REVIEW_REQUIRED` in the [register](DEPENDENCY_REGISTER.md); configuration does **not** grant redistribution approval.

Reference: [KDE Kirigami C++ setup](https://develop.kde.org/docs/getting-started/kirigami/setup-cpp/).

## 3. Standard developer commands

```bash
cmake --preset linux-release
cmake --build --preset linux-release --parallel
ctest --preset linux-release --output-on-failure
./build/presets/linux-release/apps/desktop/knetsentry --version
```

Starting `knetsentry` without options opens the M1.3 Kirigami foundation window. It is a clearly labeled **non-operational desktop preview**, not monitoring software. `--help` and `--version` do not require a graphical display. `--self-test-qml` instantiates the actual window and exits; its CTest environment uses Qt offscreen/software rendering.

For a Debug build, substitute `linux-debug`. A separate **core-only smoke build** exists for environments without Qt/KDE packages:

```bash
cmake --preset linux-core-only
cmake --build --preset linux-core-only --parallel
ctest --preset linux-core-only --output-on-failure
```

**Passing `linux-core-only` never qualifies the Qt/KDE application, QML runtime, or Ubuntu 26.04 desktop release.** Never use that preset for release sign-off. The M1.2 [hardening and analysis](HARDENING_AND_ANALYSIS.md) milestone implements Release warnings/hardening and the `linux-sanitize` preset. Full Qt GUI tests and GitHub Actions remain M1.7/M1.8 tasks; opt-in analyzer presets do not constitute CI enforcement.

## 4. M1.1 evidence and follow-up

- Full `linux-release` configure, compile, two CTest smoke cases and `--version` must be verified on the user's Ubuntu 26.04 host before issue acceptance.
- Record CMake, Ninja, GCC, Qt 6, KF6/ECM versions and any configure errors.
- `scripts/verify_m11_build.py` checks repository structure, presets, licenses and staged expectations; it is **not** a substitute for a real desktop build.
- Preserve all six M0 document-verifier passes, root MIT license, source SPDX and REUSE conventions; `CMakePresets.json` uses an explicit MIT declaration in `REUSE.toml`.
- M1.3 adds actual QML/Kirigami resources, window and app lifecycle. M1.4 adds navigation; M1.7 expands Qt/QML tests and M1.8 activates CI and official REUSE lint.

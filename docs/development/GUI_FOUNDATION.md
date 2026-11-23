<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M1.3 — Qt Quick / Kirigami Desktop Foundation

**Status:** UI shell implemented; actual GUI launch remains subject to Ubuntu 26.04 AMD64 verification. No operational SIEM, data collection, agent, or privileged functionality exists.

## Scope and design

- `apps/desktop/main.cpp` uses `QCoreApplication` for `--version`/`--help` without a display, and `QGuiApplication`/`QQmlApplicationEngine` to load the actual window.
- `apps/desktop/Main.qml` declares `Kirigami.ApplicationWindow`; M1.4 adds the GlobalDrawer and seven honest, non-operational `SectionPage.qml` destinations ([navigation guide](GUI_NAVIGATION.md)).
- `qt_add_qml_module` embeds the QML files under `io.github.spilledmilkfactory.KnetSentry` with Qt 6's standard resource prefix. There are no loose QML files loaded from an untrusted working directory.
- The QML is UI-only: no manager privileges, storage, packet capture, outbound network calls, sensor configuration, agent authentication, or fake security telemetry.
- `packaging/desktop/io.github.spilledmilkfactory.KnetSentry.desktop` is development-stage metadata, **not** an installed package or final icon. Packaging and AppStream validation remain M15.

## Runtime dependencies

Install the distribution-provided packages on Ubuntu 26.04:

```bash
sudo apt install qt6-base-dev qt6-declarative-dev extra-cmake-modules libkirigami-dev qml6-module-org-kde-kirigami
```

The normal desktop CMake preset requires Qt 6, ECM, and KF6 Kirigami at configure time. Earlier `ecm_find_qmlmodule` checks printed `qmlplugindump failed for org.kde.kirigami` even when Kirigami was present; this is an inconclusive legacy discovery mechanism. M1.3 relies on a stronger runtime check that **actually loads and instantiates** a `Kirigami.ApplicationWindow`. Do not interpret a passing configuration alone as proof that QML runs. If the runtime test fails, preserve its error diagnostics and verify the installed `qml6-module-org-kde-kirigami` package and imports; never silently skip that test or fake its success.

## Supported developer commands

```bash
cmake --preset linux-release
cmake --build --preset linux-release --parallel
ctest --preset linux-release --output-on-failure
./build/presets/linux-release/apps/desktop/knetsentry --version
./build/presets/linux-release/apps/desktop/knetsentry

cmake --preset linux-debug
cmake --build --preset linux-debug --parallel
ctest --preset linux-debug --output-on-failure

cmake --preset linux-sanitize
cmake --build --preset linux-sanitize --parallel
ctest --preset linux-sanitize --output-on-failure
```

`knetsentry_kirigami_qml_startup` is a mandatory CTest for all desktop builds. It invokes `knetsentry --self-test-qml` with `QT_QPA_PLATFORM=offscreen`, `QT_QUICK_BACKEND=software`, and `QT_QUICK_CONTROLS_STYLE=Basic` so tests need not start a visible compositor session. A passed offscreen test is not a substitute for manual launches under GNOME and KDE Plasma. The GUI requires a display when run without options; use a normal desktop session for manual testing.

Run the structure verifier and optionally exercise the binary directly:

```bash
python3 scripts/verify_m13_gui.py
python3 scripts/verify_m13_gui.py --build-dir build/presets/linux-release
```

The second form requires the built desktop executable and checks the actual embedded QML runtime. Core-only builds never qualify the GUI. These tests do not validate accessibility, full navigation, persistence, or completed security features; those are later issues.

## Manual acceptance on Ubuntu 26.04

1. Release and Debug configurations build with `-Werror` and pass all applicable tests.
2. The Kirigami runtime smoke succeeds and actually constructs `knetSentryMainWindow`.
3. The visible application opens on GNOME, closes cleanly, shows an *inactive monitoring* notice, and does not require root.
4. Confirm `--version` and `--help` work without a display (e.g. `env -u DISPLAY -u WAYLAND_DISPLAY ... --version`).
5. Confirm the same checks with the sanitizer and Clazy presets; verify QML startup failures propagate as nonzero test results.
6. Test KDE Plasma when a test environment is available; it is a v1.0 compatibility obligation, not an excuse to bypass GNOME testing.

**Risk note:** Qt and Kirigami are third-party libraries outside KnetSentry's own sanitizer instrumentation. Dependency redistribution status remains separately governed by M0.6 and the M15 release review.

## M1.3 follow-up: GCC 15 warning in Qt-generated QML cache loader

Ubuntu 26.04 GCC 15 can report `-Wnull-dereference` while compiling
Qt 6.10's generated `knetsentry_qmlcache_loader.cpp`, with the diagnostic
pointing into Qt's `QHash` implementation. Since M1.2 enables `-Werror` on
KnetSentry-owned targets, this diagnostic otherwise fails the entire desktop
build even though it does **not** originate in handwritten KnetSentry C++.

The desktop CMake target now downgrades this specific diagnostic to a visible
warning **only** for the Qt-generated QML cache loader, using CMake's
source-file `COMPILE_OPTIONS`. All other translation units retain the strict
first-party warning policy; the QML ahead-of-time compiler stays enabled.
This is a narrowly scoped build workaround, **not** evidence that the warning
is a confirmed GCC false positive or that Qt libraries have been audited.
Reassess and remove the exception when the relevant Qt/GCC versions change.

The compilation database is generated at CMake configure time, so verify the
scope **before** the build completes:

```bash
cmake --preset linux-release --fresh
python3 scripts/verify_m13_gui.py --compile-commands build/presets/linux-release/compile_commands.json
cmake --build --preset linux-release --parallel
ctest --preset linux-release --output-on-failure
python3 scripts/verify_m13_gui.py --build-dir build/presets/linux-release
```

The verifier requires the loader to retain `-Werror` and `-Wnull-dereference`
and, with GCC, also receive `-Wno-error=null-dereference`; no other C++ source
may receive that exception. Clang/Clazy must not receive the GCC-specific flag. It verifies **flags**, not runtime behavior: the QML startup
CTest and manual visible window launch remain mandatory acceptance checks.
If the Qt-generated source path changes in a future Qt version, this check
fails rather than silently allowing a broad relaxation.


## M1.3 follow-up: sanitized Kirigami startup and external library allocations

On Ubuntu 26.04 AMD64 with GCC 15.2, Qt 6.10.2, and Kirigami 6.24.0,
`knetsentry_kirigami_qml_startup` successfully creates the real window but
LeakSanitizer reports 5,913 bytes in 86 allocations whose recorded stacks
originate in **Fontconfig**, the **Qt font database**, and the system-installed
**Kirigami controls QML plugin**. This is not a verified KnetSentry allocation;
we must **not** infer that the upstream libraries are leak-free either.

Only the sanitizer build's two QML-only tests (`knetsentry_kirigami_qml_startup` and `knetsentry_primary_navigation`) receive
`LSAN_OPTIONS=suppressions=.../tests/sanitizers/lsan_qml_third_party.supp`.
The file contains **only** `leak:libfontconfig.so.1` and
`leak:libKirigamiControlsplugin.so`, matching the two observed external
allocation stacks. `ASAN_OPTIONS=detect_leaks=1` is retained, as are ASan
and UBSan memory/undefined-behavior checks. These rules do **not** apply to
other CTest cases (apart from the separate intentional-leak negative control,
which uses the same file), to manually launched executables, or to release builds.

Every sanitizer build includes `knetsentry_lsan_negative_control`: it runs
an isolated test-only executable that **intentionally** leaks 1337 bytes, with
the **same suppression file** and leak detection enabled. The wrapper
requires LeakSanitizer to report the intentional leak and exit unsuccessfully;
otherwise the verification test fails. This guards against accidentally
masking all first-party memory leaks.

```bash
cmake --preset linux-sanitize --fresh && \
cmake --build --preset linux-sanitize --parallel && \
ctest --preset linux-sanitize --output-on-failure
python3 scripts/verify_m13_lsan.py

# Optional: inspect the unsuppressed upstream diagnostic. This is expected
# to return nonzero on the affected Qt/Kirigami versions, so record it as
# diagnostic evidence rather than as a qualification run:
QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software QT_QUICK_CONTROLS_STYLE=Basic \
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
./build/presets/linux-sanitize/apps/desktop/knetsentry --self-test-qml
```

A new leak report not matching these **two** entries is a failure requiring
investigation. Reevaluate and ideally remove the suppressions following Qt,
Kirigami, Fontconfig, or compiler upgrades; update documented evidence when
upstream behavior changes. Do not generalize them to an entire Qt library,
additional tests, or project-wide sanitizer settings. A passing run proves
only that this fixture exercises an operational QML startup while known
external leak stacks are excluded; it does not prove the libraries leak-free.

References: [LeakSanitizer suppressions](https://clang.llvm.org/docs/LeakSanitizer.html).

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M1.7 — Initial CTest and Qt Test Suites

**Scope:** Foundational tests for Ubuntu 26.04 AMD64. These are developer
qualification checks, not a security-product release certification. SIEM
services, privileged operations, network authorization, and live telemetry
remain unimplemented and must not be represented as passing security tests.

## Test architecture

1. **Qt-independent core:** `knetsentry_core_build_identity`,
   `knetsentry_structured_diagnostics`, and `knetsentry_core_boundary_contract`
   exercise actual compiled C++23 code. The new boundary test confirms
   private text is never serialized, the maximum uint64 count stays intact,
   invalid event IDs fail without partial output, and logger sequences are
   per instance. All checks execute in Release, not disabled `assert()` calls.
2. **Qt Test model:** `knetsentry_qt_model_contract` runs a genuine
   `QAbstractListModel` using Qt Test's `QCOMPARE`, `QVERIFY`,
   `QSignalSpy`, and `QAbstractItemModelTester`. The production-owned
   `SectionCatalogModel` provides a *read-only, non-operational* fixed list
   of the seven primary application section identifiers/titles. It is an
   initial model contract, not a network assets or security-event model;
   the existing QML drawer remains the navigation authority for M1.7.
   Out-of-range role access and unauthorized edits must fail.
3. **Qt Test application:** `knetsentry_qt_application_lifecycle` launches
   the actual desktop executable using Qt's `QProcess` with display
   variables removed. `--version` and `--help` must work headlessly;
   `--self-test-qml` must load real Qt/Kirigami QML and produce the expected
   fixed-code structured lifecycle records. This is a separate Qt Test
   executable, not a fake QML engine.
4. **Existing GUI regression:** QML startup, 28-route navigation,
   actual PageRow warning check, visual tokens, and desktop diagnostics
   continue running under their existing CTest names.
5. **Configured test inventory:** `knetsentry_configuration_contract`
   executes `verify_m17_suites.py --build-dir <build>` to inspect the
   *actual* CMakeCache and `ctest -N` output. It rejects zero tests,
   missing/extra tests, incomplete desktop qualification, missing
   warnings-as-errors, and disabled release hardening. Qt Test must be
   installed and found for all full-desktop configurations, with no
   silent fallback to core-only testing.

## Expected test counts and scope

| Preset | Expected CTest count | Qt model | Qt application | Negative LSan control |
| --- | ---: | --- | --- | --- |
| `linux-release` | 13 | Required | Required | Not instrumented |
| `linux-debug` | 13 | Required | Required | Not instrumented |
| `linux-clazy` | 13 | Required | Required | Not instrumented |
| `linux-analysis` | 13 | Required | Required | Not instrumented |
| `linux-sanitize` | 10 | Required | Covered by preexisting sanitizer QML startup and navigation tests | Required |
| `linux-core-only` | 5 | Not built (no Qt dependency) | Not built | Not instrumented |
| `linux-sanitize-core-only` | 6 | Not built (no Qt dependency) | Not built | Required |

The new QProcess-based Qt Test QML invocation is intentionally **not**
registered in the sanitizer preset. Existing sanitized `--self-test-qml`
and `--self-test-navigation` continue verifying actual Qt/Kirigami runtime
with only the *two* previously justified third-party LSan suppressions.
Do not extend suppressions automatically to additional Qt Test processes.
Qt Test model verification itself remains instrumented, as it only uses Qt
Core and the first-party read-only catalog.

## Supported Ubuntu execution

Install the distribution's Qt6 Test development support (usually included in
`qt6-base-dev`, verify through `Qt6::Test` CMake discovery). Execute:

```bash
cmake --preset linux-release --fresh && \
cmake --build --preset linux-release --parallel && \
ctest --preset linux-release --output-on-failure

python3 scripts/verify_m17_suites.py --build-dir build/presets/linux-release
ctest --test-dir build/presets/linux-release --output-on-failure -L qt
```

Repeat for `linux-debug`, `linux-sanitize`, `linux-clazy`,
`linux-analysis`, `linux-core-only`, and `linux-sanitize-core-only`.
Each required preset must run successfully rather than being replaced with
an unrelated preset's result. `ctest -N` is **discovery only** and cannot
qualify a test that has never executed. The `noTestsAction: error` preset
contract remains mandatory. For manual GUI acceptance, verify navigation
and lack of fabricated telemetry on GNOME; KDE Plasma qualification remains
future work. GUI runtime evidence is only available on a Qt/Kirigami-enabled
host, not from a core-only build.

## Privacy, negative cases, and limitations

- All catalog entries are fixed section labels; test cases contain no real
  LAN data, credentials, or private evidence.
- Negative model tests reject invalid indexes, unknown roles and mutation.
- Diagnostic tests reject invalid enum codes and prevent secret serialization.
- Configuration testing rejects missing registrations, zero tests, or disabled
  hardening rather than reporting PASS.
- Qt framework output is not sanitized by KnetSentry's logger. Review
  stdout, stderr, sanitizer reports, and public CI artifacts for private data.
- Tests exercise real C++/Qt/QML components but do not verify future manager,
  sensors, network permissions, evidence storage, or authorization.
- Source-only verifier PASS is **not** a substitute for runtime/CTest PASS.

## Verification evidence

Store the source revision/commit, toolchain, preset, exact command, test
count, outcomes, relevant sanitized logs, and any EXCEPTION/BLOCKED reasons
following [`VERIFICATION_EVIDENCE.md`](VERIFICATION_EVIDENCE.md). `VG-27`
traceability remains a documentation/evidence requirement, not a claim that
public GitHub Actions exists; CI setup is planned for M1.8.

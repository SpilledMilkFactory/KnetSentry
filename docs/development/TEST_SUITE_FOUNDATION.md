<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M1.7 — Initial CTest and Qt Test Suites

> Historical baseline and design contract. For current implemented behavior and
> acceptance evidence, see [project status](../PROJECT_STATUS.md). Future requirements
> and original milestone-specific test counts below are not release claims.

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
   per instance. An intentionally unapproved diagnostic event is constructed
   with `std::bit_cast` from an 8-bit representation to avoid analyzer warnings
   about an out-of-range enum *cast*, while still testing logger rejection.
   All checks execute in Release, not disabled `assert()` calls.
2. **Qt Test model:** `knetsentry_qt_model_contract` runs a genuine
   `QAbstractListModel` using Qt Test's `QCOMPARE`, `QVERIFY`,
   `QSignalSpy`, and `QAbstractItemModelTester`. The production-owned
   `SectionCatalogModel` provides a *read-only, non-operational* fixed list
   of the seven primary application section identifiers/titles. It is an
   initial model contract, not a network assets or security-event model;
   the existing QML drawer remains the navigation authority for M1.7.
   Out-of-range role access and unauthorized edits must fail. The one-column
   assertion uses the public `QAbstractItemModel` virtual interface because
   `QAbstractListModel::columnCount` is private in the supported Qt 6 headers.
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
   warnings-as-errors, and disabled release hardening. It also inspects
   CTest JSON command discovery and requires actual executable files, so
   a failed build cannot pass merely because test names are registered.
   This remains discovery/build evidence, not proof that tests ran. Qt Test must be
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
After a successful build, the M1.7 verifier now rejects missing test binaries
rather than accepting `ctest -N` names alone. A newly configured but not yet
built tree may therefore report FAIL by design. It is important to build
before running `verify_m17_suites.py --build-dir`.

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

## M1.7 Qt 6 and analyzer corrective follow-up

The first M1.7 Ubuntu desktop builds failed in `section_catalog_qtest.cpp`:
`model.columnCount()` was inaccessible because Qt 6's `QAbstractListModel`
override is private and requires a parent argument. The model itself was not
shown defective. Call `columnCount()` through the public `QAbstractItemModel`
base interface; do **not** modify production model visibility or weaken
compiler warnings to accommodate the test. Release, Debug, Clazy, sanitizer,
and analysis must all compile the test normally.

The analysis preset additionally warned on an intentionally out-of-range
`static_cast<DiagnosticEvent>(255)` in the core negative-control test.
Construct that test-only invalid representation with `std::bit_cast` from
`std::uint8_t{255}`; retain the logger's rejection and no-partial-output checks.
Neither first-party security checks nor analyzer configuration is relaxed.

Finally, CTest registration alone was insufficient evidence of a completed
build: `ctest -N` listed the two Qt tests after the compiler failed, even
though their executables did not exist. The configured verification now
requires every registered CTest command to resolve to an executable on disk;
**that is still not evidence that the tests have passed**, which requires an
actual `ctest --output-on-failure` run on the same revision.

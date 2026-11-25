<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Planned Verification Gates and Ownership Matrix

> Historical baseline and design contract. For current implemented behavior and
> acceptance evidence, see [project status](../PROJECT_STATUS.md). Future requirements
> and original milestone-specific test counts below are not release claims.

**Issue:** M0.7 / GitHub #7. **State:** all `VG-01`–`VG-30` cases
are future gates; none has been executed by the M0.7 documentation update.
The existing M0.3–M0.6 documentation verifiers are real and must still pass.

These gate IDs are stable *verification specifications*, not GitHub issues,
not test executable names, and not test results. M1 and later issues will
convert each applicable gate into real commands and evidence.

| Gate | Test or review scope | Implementation owner | Planned observable outcome | Required evidence |
| --- | --- | --- | --- | --- |
| `VG-01` | C++23 build and CMake presets | M1.1 | Construct app in clean Ubuntu CMake/Ninja workspace; preset names and compiler versions recorded | Configure/build log, compile_commands.json |
| `VG-02` | Ownership and resource RAII | M1.7 | Unit fixtures for resource ownership and failure cleanup; review raw pointer exceptions | CTest cases, targeted review |
| `VG-03` | Untrusted bounds and overload | M2.8 | Oversized malformed and cancelled IPC/event inputs rejected within limits | Negative fixtures, resource counters |
| `VG-04` | Concurrency and shutdown | M2.8 | Race/shutdown/restart tests and planned concurrency analysis | CTest and trace logs |
| `VG-05` | Reviewed cryptography and secrets | M4.8 | Untrusted credentials, TLS failures and secret marker leakage checks | Auth denial tests, redaction logs |
| `VG-06` | Compiler warnings gate | M1.2 | GCC/Clang diagnostics under reviewed first-party flags | Build logs, warnings inventory |
| `VG-07` | ASan and UBSan | M1.2 | Instrumented CTest runs with failure status and symbolized reports | Sanitizer logs, test counts |
| `VG-08` | Release binary hardening | M15.5 | Inspect target ELF protections and released dependency linkage | ELF inspection results, package hashes |
| `VG-09` | Privilege and local IPC | M2.8 | GUI unprivileged; unauthorized IPC, service capabilities and policy operations denied | ACL and process integration tests |
| `VG-10` | Monitoring and restricted egress | M3.7 | Approved sensor observation; forbidden scope and unapproved feed request denied | Namespace captures, policy logs |
| `VG-11` | CTest unit harness | M1.7 | CTest discovers expected unit fixtures and reports actual pass/fail counts | CTest JUnit/results |
| `VG-12` | Qt Test model coverage | M1.7 | C++ models and Qt signal/slot tests execute deterministically | Qt Test results |
| `VG-13` | QML and GUI smoke | M1.7 | Qt Quick Test navigation/state; QML startup and import errors surfaced | QML test and startup logs |
| `VG-14` | Process and storage recovery | M6.9 | IPC restart and raw-first mount/index failure tests in disposable fixtures | Fault-injection evidence |
| `VG-15` | Security denial paths | M2.8 | Unauthorized, malformed and timeout cases added with each security surface | Security regression fixtures |
| `VG-16` | No private CI artifacts | M1.8 | Synthetic telemetry used; secret and privacy markers do not leak in public logs | Log redaction review |
| `VG-17` | clang-tidy | M1.8 | Run versioned clang-tidy checks on compilation database | Analyzer findings, triage |
| `VG-18` | Clazy for Qt | M1.8 | Run compatible Clazy checks on actual Qt C++ targets | Analyzer findings, triage |
| `VG-19` | qmllint | M1.8 | QML modules lint without unreviewed errors | qmllint output |
| `VG-20` | Formatting | M1.8 | clang-format/qmlformat and source conventions checked | Formatting check result |
| `VG-21` | Fuzz targets | M13.2 | Bounded fuzzing and regression seeds cover exposed parsers | Fuzzer seed/coverage/crash triage |
| `VG-22` | REUSE and dependency approval | M1.8 | Official reuse lint; dependency lock/provenance and license policy checks | REUSE output, dependency register |
| `VG-23` | Actions token/action security | M1.8 | Workflow uses full SHA pins and minimal job permissions | Workflow inspection |
| `VG-24` | PR isolation | M1.8 | Untrusted PR has no secrets or privileged host network access | PR workflow permission test |
| `VG-25` | Required-check integrity | M1.8 | Missing tool, zero test count and failing step fail job | Deliberate negative CI fixture |
| `VG-26` | Network fixture containment | M3.6 | Namespace firewall/capture fixtures do not modify host networking | Namespace diff and capture review |
| `VG-27` | Traceable test evidence | M1.7 | Record source SHA, environment, exact command, sanitized outcome | Gate evidence record |
| `VG-28` | Release signing and artifact verification | M15.9 | Approval-controlled publishing uses approved source and verified package hashes | Signing workflow and hashes |
| `VG-29` | PR threat/security review | M1.9 | Reviewer answers boundary/privacy questions; exceptions tracked with expiry | PR template and issue evidence |
| `VG-30` | Release/performance risk signoff | M15.8 | Check M0.5 workloads and residual risks; block on unresolved release finding | M13/M14/M15 signed findings |

## Requirements to gates

The [development contract](../../DEVELOPMENT_CONTRACT.md) assigns each of
`KS-DEV-001`–`KS-DEV-040` a planned `VG-##` gate. Those assignments are
normative: a future test may cover several requirements, but it must report
which specific conditions it verified and which are still untested. The
[threat verification plan](../security/THREAT_VERIFICATION_MATRIX.md) retains
independent `TV-*` tests; [network tests](../security/NETWORK_SCOPE_VERIFICATION_PLAN.md)
and [M0.5 workloads](BENCHMARK_PLAN.md) retain their own IDs. Passing a
`VG-*` code-style gate is never a substitute for a `TV-*` network control or
an installed-binary test.

## Gate transitions and test reliability

Before implementation: `PLANNED`. If a tool or required fixture is missing:
`BLOCKED`. A discovered test suite with zero tests is not PASS. A failed or
suppressed gate remains FAIL or EXCEPTION with the corresponding reason,
owner, and review date. The test must run against the intended revision;
source drift invalidates acceptance evidence. As a test becomes activated
its exact command, environment, redacted report and GitHub required-check
name must be recorded in the
[evidence contract](VERIFICATION_EVIDENCE.md).

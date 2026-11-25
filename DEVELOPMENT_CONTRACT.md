<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Secure Development and Verification Contract

> Historical baseline and design contract. For current implemented behavior and
> acceptance evidence, see [project status](docs/PROJECT_STATUS.md). Future requirements
> and original milestone-specific test counts below are not release claims.

**Issue:** M0.7 / GitHub #7. **Scope:** project requirements, not implemented
security controls or completed build/test workflows. This contract is subordinate
to the accepted [network requirements](docs/security/NETWORK_SCOPE_REQUIREMENTS.md),
[threat model](docs/security/THREAT_MODEL.md), and
[architecture](docs/architecture/SYSTEM_ARCHITECTURE.md); it does not relax them.

## 1. Enforcement and activation

A gate marked for **M1.1** or later is a binding *future implementation*
requirement, not a currently executable command. At M0.7 the only executable
acceptance checks are the existing offline document verifiers and the new
M0.7 verifier. M1 establishes actual CMake/Qt source, build presets and CI.
Once an applicable gate has been activated, a skipped, absent, crashed or
misconfigured test is **not** a PASS. The owner must repair the test or document
a scoped, time-bounded exception where allowed by
[change review policy](docs/development/SECURITY_REVIEW_PROCESS.md).
A new security control requires denial-path evidence as well as happy-path
behavior. Network isolation and privilege containment require tests on the
actual supported Linux configuration; a mocked policy decision alone is
insufficient evidence of enforcement.

M0.7 documentation verification checks consistency of this planned contract.
It cannot qualify a running SIEM or a release artifact.

## 2. Traceable development requirements

Each `KS-DEV-*` requirement has a future implementation owner and a planned
`VG-*` verification case in the [verification matrix](docs/development/VERIFICATION_MATRIX.md).

| ID | Topic | Requirement | Activation owner | Planned gate |
| --- | --- | --- | --- | --- |
| `KS-DEV-001` | C++ language and compiler | Use C++23 with documented GCC/Clang version baselines; isolate C and platform-specific code. | M1.1 | `VG-01` |
| `KS-DEV-002` | Ownership and lifetime | Prefer RAII, smart ownership, scoped resources, and explicit borrowed views; no unchecked lifetime assumptions. | M1.1 | `VG-02` |
| `KS-DEV-003` | Untrusted inputs | Validate size, encoding, type, nesting and provenance before allocating or interpreting untrusted inputs. | M2.3 | `VG-03` |
| `KS-DEV-004` | Bounded execution | Set explicit quotas, deadlines, queue capacities and cancellation for parsers, workers and I/O. | M2.3 | `VG-03` |
| `KS-DEV-005` | Concurrency | Define thread ownership, locking and shutdown order; test races and cancellation paths. | M2.8 | `VG-04` |
| `KS-DEV-006` | Crypto and secrets | Use reviewed cryptographic libraries; never invent primitives, log keys or hardcode secrets. | M4.2 | `VG-05` |
| `KS-DEV-007` | Compiler diagnostics | Use documented high-signal GCC/Clang warnings and warnings-as-errors on first-party targets after baseline stabilization. | M1.2 | `VG-06` |
| `KS-DEV-008` | Build presets | Provide versioned CMake+Ninja configure/build/test presets and an out-of-tree build. | M1.1 | `VG-01` |
| `KS-DEV-009` | Sanitizer builds | Maintain reproducible ASan and UBSan checks on supported targets; do not claim they cover all defects. | M1.2 | `VG-07` |
| `KS-DEV-010` | Release hardening | Evaluate PIE, RELRO, stack protections, fortified libc, and compiler/toolchain applicability; verify actual ELF outputs before release. | M1.2 | `VG-08` |
| `KS-DEV-011` | Privilege boundaries | Keep Qt/QML outside privileged services; gate capture, policy, agent and IPC operations with least authority. | M2.7 | `VG-09` |
| `KS-DEV-012` | Network authority | Test distinct observation scope, authenticated LAN transport, and opt-in restricted intelligence egress. | M3.7 | `VG-10` |
| `KS-DEV-013` | Unit testing | Register deterministic unit tests in CTest with failure status and reproducible fixtures. | M1.7 | `VG-11` |
| `KS-DEV-014` | Qt tests | Use Qt Test for C++ models, signals, threading and authorized GUI-to-manager contracts. | M1.7 | `VG-12` |
| `KS-DEV-015` | QML tests | Use Qt Quick Test for navigation, state, accessibility fundamentals and reduced-motion behavior when present. | M1.7 | `VG-13` |
| `KS-DEV-016` | Integration testing | Exercise actual process boundaries and protocol failures using isolated, authorized fixtures. | M2.8 | `VG-14` |
| `KS-DEV-017` | Security negative tests | Every security control requires denial, malformed-input and degradation cases as appropriate. | M2.8 | `VG-15` |
| `KS-DEV-018` | Data confidentiality | Never use actual private home telemetry, credentials or packet payloads in public CI or test artifacts. | M1.7 | `VG-16` |
| `KS-DEV-019` | Static analysis | Use clang-tidy with a versioned rule configuration; triage warnings with owner and rationale. | M1.8 | `VG-17` |
| `KS-DEV-020` | Qt-aware analysis | Use compatible Clazy checks for affected Qt C++ code, not non-Qt services. | M1.8 | `VG-18` |
| `KS-DEV-021` | QML lint | Run qmllint on QML modules and require QML diagnostics to be dispositioned. | M1.8 | `VG-19` |
| `KS-DEV-022` | Formatting | Enforce versioned clang-format, qmlformat and relevant Python/Markdown formatting policies. | M1.8 | `VG-20` |
| `KS-DEV-023` | Fuzzing | Add persistent regression seeds and bounded fuzz targets at untrusted parsing boundaries. | M13.2 | `VG-21` |
| `KS-DEV-024` | License/dependency checks | Run official reuse lint and validate dependency provenance, versions, and approval before adding binaries. | M1.8 | `VG-22` |
| `KS-DEV-025` | Actions permissions | Use minimum GITHUB_TOKEN permissions, commit-SHA-pinned external actions and reviewed workflows. | M1.8 | `VG-23` |
| `KS-DEV-026` | Untrusted PR isolation | Do not expose secrets, write tokens, elevated capabilities or production networks to untrusted PR code. | M1.8 | `VG-24` |
| `KS-DEV-027` | Required check integrity | Fail on applicable test/tool errors; no permissive `or-true` masking, hidden skips or success-from-empty-test runs. | M1.8 | `VG-25` |
| `KS-DEV-028` | Network fixture isolation | Run capture and nftables/route tests in isolated authorized fixtures, not the developer LAN by default. | M3.6 | `VG-26` |
| `KS-DEV-029` | Provenance | Record source SHA, dependency identifiers, toolchain, runner, test command and sanitized results. | M1.8 | `VG-27` |
| `KS-DEV-030` | Release workflow separation | Release-signing and publishing permissions exist only in reviewed, approval-gated release workflows. | M15.9 | `VG-28` |
| `KS-DEV-031` | Change review | Every PR declares affected trust boundaries, privileges, monitoring scope, PII and data retention impacts. | M1.9 | `VG-29` |
| `KS-DEV-032` | Threat traceability | New security exposures update TH/TB/KS-NET mappings or provide a documented not-applicable rationale. | M1.9 | `VG-29` |
| `KS-DEV-033` | Privacy verification | Check for credential/telemetry disclosure through logs, QML, reports, crash dumps and CI artifacts. | M1.6 | `VG-16` |
| `KS-DEV-034` | Evidence requirements | Record expected/observed results, source revision, environment and failures for security claims. | M1.7 | `VG-27` |
| `KS-DEV-035` | Risk decisions | Security findings use severity, owner and remediation; critical unresolved release risks block publication. | M13.9 | `VG-30` |
| `KS-DEV-036` | Exceptions | Temporary suppressions require an issue, owner, reason, limited scope and revisit date; never waive core invariants. | M1.9 | `VG-29` |
| `KS-DEV-037` | Performance honesty | Use M0.5 reference profiles and separate packet/s, source records/s and normalized event/s metrics. | M14.1 | `VG-30` |
| `KS-DEV-038` | Storage recovery | Test independently selectable raw/index storage, mount loss, raw-first durability and recovery with synthetic data. | M14.4 | `VG-14` |
| `KS-DEV-039` | Release artifact tests | Test installed packages, services, licenses, notices and SBOM against exact release artifacts. | M15.5 | `VG-28` |
| `KS-DEV-040` | Security release gate | M13–M15 security and integrity checks cannot be replaced by documentation-only verifier passes. | M15.8 | `VG-30` |

## 3. Security-first issue acceptance

A PR that implements production code must carry: (a) a scope summary and
associated GitHub issue; (b) impact on trust, privilege, privacy, network and
storage; (c) new/updated tests including negative cases; (d) actual executed
results; (e) source/dependency provenance; (f) documentation updates; and
(g) review sign-off. Documentation-only changes use the offline documentation
verifiers and link checks; they do not falsely report CTest/GUI tests as passed.

A developer may work alone, but must not claim independent review when only
self-review occurred. Security-critical changes and release sign-off require
explicit review evidence and unresolved-risk assessment; a later independent
review may be required by project policy before publication.

## 4. Standard future development commands

Once M1.1/M1.2/M1.7 have introduced and tested the named presets:

```bash
cmake --preset linux-release
cmake --build --preset linux-release --parallel
ctest --preset linux-release --output-on-failure

cmake --preset linux-sanitize
cmake --build --preset linux-sanitize --parallel
ctest --preset linux-sanitize --output-on-failure
```

**These commands are illustrative until presets exist; do not execute them as
M0.7 acceptance tests.** See the
[toolchain strategy](docs/development/TOOLCHAIN_TEST_MATRIX.md) for sanitizer
limitations, OS hardening, Qt, and isolated privileged tests.

## 5. Evidence and release restrictions

The [evidence schema](docs/development/VERIFICATION_EVIDENCE.md) defines a
portable result template and separates `PLANNED`, `PASS`, `FAIL`, `BLOCKED`,
`NOT_APPLICABLE`, and `EXCEPTION` states. A required gate that never ran must
not be recorded as PASS. No command or documentation result is treated as a
security guarantee. The [CI security policy](docs/development/CI_SECURITY_POLICY.md)
requires least-privilege, PR isolation, and approval-gated release jobs.

M13 security assessment, M14 reliability tests, M15 artifact audits and
supported-system deployment evidence remain required before v1.0.0. The
[license policy](docs/development/LICENSING_POLICY.md) and
[dependency approvals](docs/development/DEPENDENCY_APPROVAL_POLICY.md)
remain separately binding.

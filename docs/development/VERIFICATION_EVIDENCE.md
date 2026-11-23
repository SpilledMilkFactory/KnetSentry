<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Verification Evidence and Gate Result Schema

**Status:** M0.7 reporting format. No build, runtime, or release evidence is
created by adopting this schema. The prior M0.3–M0.6 documentation verifiers
remain the only applicable existing automated checks.

## Result states

| Value | Meaning | Acceptable as a required PASS? |
| --- | --- | --- |
| `PLANNED` | Future test or check, not implemented | No |
| `PASS` | Check executed successfully against recorded code and environment | Yes, only for the named scoped check |
| `FAIL` | Executed and did not meet requirement | No |
| `BLOCKED` | Could not execute or precondition unmet | No |
| `NOT_APPLICABLE` | Reviewed as irrelevant to a *specific* change with rationale | Not equivalent to a PASS |
| `EXCEPTION` | Documented, time-bounded allowance where policy permits | Not equivalent to a PASS |

A check that discovers zero tests, cannot find its required binary, crashes,
never runs due to matrix filters, or reports incomplete coverage must not
receive a `PASS`. Distinguish expected capability from empirically tested
control and from independent artifact verification.

## Reusable evidence record template

```yaml
# Illustration only. Not an executed check or an actual evidence file.
issue: "M<issue>"
commit: "<full source commit SHA>"
source_tree: "<working-tree state, if local>"
gate: "VG-XX"
requirements: ["KS-DEV-XXX"]
result: "PLANNED"
owner: "<reviewer or implementing role>"
review_independence: "self-review | independent | not reviewed"
environment:
  operating_system: "<OS image and version>"
  architecture: "<amd64>"
  compiler: "<compiler and version>"
  qt: "<Qt version or not applicable>"
  dependencies: "<versioned inventory or reference>"
execution:
  command: "<exact command>"
  expected: "<predeclared expected outcome>"
  observed: "<actual result, counts and limitations>"
  start_utc: "<timestamp>"
  duration_seconds: "<measured duration>"
artifacts:
  logs: ["<redacted log reference>"]
  reports: ["<test/coverage/SARIF reference>"]
  artifact_hashes: ["<SHA-256 when applicable>"]
exceptions: []
open_risks: []
```

This is a *template*, not a committed YAML evidence result. Actual artifacts
must be redacted, integrity-checked and tied to the tested commit and
dependency state. Sanitizer reports and CI logs may include personal paths,
credentials and packet contents, so review before publication. Store
potential exploit and vulnerability material in a restricted channel.

## Minimum evidence by scope

- **Documentation-only M0.7:** four previous offline verifiers, new M0.7
  verifier, Markdown link/SPDX checks, patch integrity and Git whitespace.
- **Code-bearing M1/M2:** build/test commands, executed CTest counts, Qt/QML
  results, analyzer status and exact source SHA.
- **Security-sensitive M3–M13:** attack/negative case, test isolation proof,
  denied operations, audit logs, threat IDs and host-level enforcement proof
  where needed.
- **Release M15:** artifact digests, SBOM, license/release clearance, installed
  package smoke results, reviewer sign-off and remaining-risk assessment.

The [verification matrix](VERIFICATION_MATRIX.md) maps planned gate IDs to
owners and requirements. The [M0.5 benchmark template](BENCHMARK_RESULT_TEMPLATE.md)
adds workload-specific metrics, not an alternate security pass mechanism.

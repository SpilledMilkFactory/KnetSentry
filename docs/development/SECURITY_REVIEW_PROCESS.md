<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Security Impact Review and Exception Policy

**State:** M0.7 approved *process design*, not evidence that future pull
requests have received these reviews. M0.8 will formalize repository
participation/governance and M1.9 adds templates to support this policy.

## Review intake for each implementation PR

A PR description must identify its GitHub issue, changed modules/interfaces,
new dependencies, build/test commands, and affected security boundaries.
Specific answers are mandatory for changes touching any of the following:

| Impact question | Required response |
| --- | --- |
| Input trust | Can attacker-controlled packet/record/API/QML/AI data reach the change? What validation and limits apply? |
| Authority | Does it cross a `TB-*` boundary or alter a `C-*` or `I-*` contract? Does it grant capabilities, file permissions or IPC operations? |
| Monitoring | Does it alter approved LAN observation, optional-agent transport, or restricted threat-feed Internet egress? |
| Privacy | Does it retain raw payloads, change redaction, increase export reach or expose telemetry in debug/CI? |
| Storage | Does it alter raw-first durability, path authorization, mount identity, migration, retention or evidence provenance? |
| Operations | What happens on timeouts, loss, missing sources, disk-full or invalid authorization? Are failures observable? |
| Test evidence | Which unit/negative/integration/fuzz/GUI tests were run, on what source revision and platform? |
| Threat evolution | Which `TH-*`, `TB-*`, `KS-NET-*`, and `KS-PERF-*` contracts change, if any? |

Review cannot equate a verified green GUI with security correctness.
A security-sensitive PR requires deliberate authorization and negative-test
review; a new authenticated connection without denial-path tests is not
complete. If no existing threat captures a new attack surface, create a
tracked threat and a future/actual verification owner. Test results must
come from the exact revised code, not an older local build.

## Finding severity and disposition

| Severity | Example | Required action |
| --- | --- | --- |
| Critical | Demonstrated unauthorized root action, arbitrary private-data exfiltration or critical trust-boundary bypass | Block affected merge/release; create restricted security report |
| High | Exploitable packet parser crash or unauthorized protected event access | Block merge for affected functionality; remediate and retest |
| Moderate | Bounded denial of service, incomplete audit trail or material coverage error | Track owner, target fix and explicit acceptance decision; usually resolve before release |
| Low | Minor hardening opportunity with no demonstrated boundary violation | Track and prioritize with evidence |
| Informational | Documentation or code-quality observation | Record as improvement or accepted with rationale |

Classification depends on actual preconditions, exploitability, exposure and
impact, not solely on scanner output. Unknown severity is `UNASSESSED`, not
assumed low. Never post secret-bearing proofs of concept to a public issue.
Use the project's coordinated disclosure process from M0.8.

## Exception controls

Any allowed temporary deviation must record issue/PR, owner, scope, exact
check or dependency, justification, compensating control, expiry/review
date, and validation plan. Do not use `continue-on-error` to hide it. An
exception does **not** make a failed check PASS. It must appear in the test
and release evidence as `EXCEPTION` and be assessed again at M13/M15.

No exception may silently waive: unauthorized packet capture, administrative
authorization, private evidence disclosure, AI or feed worker authority,
claimed observation coverage, or a confirmed critical release vulnerability.
A release-blocking security finding cannot be converted into acceptable
risk through an undocumented note or changed severity label.

## Review independence

The initial maintainer may perform a documented self-review, but must label
it correctly. Where external review is unavailable, record the limitation
and security risk; do not misrepresent it as independent approval. High-impact
security changes should seek an independent reviewer when practicable. Formal
release sign-off uses the evidence and risk register from M13, not a generic
checkbox in GitHub.

See the [contract](../../DEVELOPMENT_CONTRACT.md),
[security principles](../security/SECURITY_PRINCIPLES.md), and
[verification evidence format](VERIFICATION_EVIDENCE.md).

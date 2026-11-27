<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M7.1 — Deterministic detection engine

Issue #60; bounded offline rule evaluation against the M6.2 mapping revision 1
(OCSF-aligned 1.4.0 subset). Target qualification accepted.

## Interface and trust

`KnetSentry::Detection` exposes `knetsentry::detection::Engine`. The trusted
caller supplies typed rules and one minimized `storage::EventSummary` from
its selected store and bounded cursor/page. The engine does not fetch evidence,
authenticate it, decide access, change storage, or schedule evaluation.
`VerifiedStored` is a caller assertion of authorized, validated provenance,
not proof of durability, endpoint truth or completeness. `Unverified` refuses
rule evaluation. Coverage is caller-provided Unknown, Partial or SourceObserved;
SourceObserved means a source was observed, not complete monitoring coverage.
Findings contain only rule ID, version, store-scoped evidence ID and supplied
coverage. The caller must retain store identity and mapping context. Synthetic
reference-store tests explicitly simulate the trusted caller; they are not live
monitoring. No GUI, AI, network, clock, response or database mutation is used.

## Rules and bounds

The factory accepts up to 64 rules and rejects the entire configuration if any
rule is invalid. IDs contain 1–64 lowercase ASCII letters, digits, hyphens,
underscores or dots; version is nonzero; duplicate IDs are refused even when
versions differ. A rule selects a known activity (Logon/Logoff), known outcome
(Success/Failure), or both; optionally an exact allowlisted authentication unit
(maximum 128 bytes). All predicates are conjunctive. Empty source means any
supported authentication source; there are no patterns, regex, scripts,
implicit rules or executable content. Empty rule sets report NoRules for
supported trusted events. Configuration is copied and sorted by ID, producing
reproducible order independent of input order. No rule is persisted or installed.

Evaluation checks the mapping revision's valid source, class, activity, status,
category, severity and mapping combinations and bounded IDs/timestamps. Source
milliseconds may be zero for valid submillisecond observations. Receipt time
must be positive. The source clock is not used for correlation or scheduling.
Nonclassified, metadata-only, unmapped audit and redacted observations are
Unsupported, never interpreted as a successful negative match. A known
predicate mismatch rules out a match even if another predicate is unknown;
otherwise an unknown required predicate increments indeterminate rather than
matching or becoming a negative outcome. Evaluated counts definite matches and
nonmatches. Indeterminate is separate; their sum is the rule count for an
Evaluated result. Invalid, Unverified, Unsupported and NoRules produce no
findings. A matching finding describes an observation, not proof of an incident.

Each call evaluates at most 64 rules and emits at most 64 findings; string
comparisons have fixed input ceilings. The engine has no mutable per-event
state or unbounded queue; the caller owns bounded paging, scheduling, storage
identity, retries and deduplication. Repeating an event repeats the same output;
no alert persistence, suppression, correlation or delivery is implemented.
Allocation failures propagate and must never be translated into a clean result.

## Qualification

`knetsentry_detection_contract` composes synthetic canonical records, the
production reference store, normalization, bounded search and the engine.
It tests exact findings, independent rule order, repeatability, unknown fields,
redaction, unsupported modes, trust, malformed summaries, malformed rules,
duplicate IDs, configuration ownership, empty policy and maximum fanout.
The initial Ubuntu GCC 15.2 Release build reported `-Wdangling-pointer`
while optimizing temporary expected-finding vectors in the regression. The
follow-up compares named evaluation results using size-guarded, field-by-field
finding assertions, preserving exact match counts, order, identity, version,
evidence and coverage. No warning suppression, optimization change, or
production detection change is introduced. Target-host qualification passed.

M7.1 maintainer acceptance (2026-11-27 UTC, applied working tree based on `bd03c2c` with the two corrective files modified) recorded 139 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED, all 484 configured CTest executions, 63 structural verifiers, 60 repeated Release and 30 repeated sanitized executions, clean Release/analysis-build diagnostics, GUI independence, installed manager equality, actual private mount regression and nine green hosted checks (`a71d775`). Manual GUI regression and merge were reported successful.

All fixtures are synthetic. The target is all seven presets and existing
security, sanitizer and GUI regressions; no privileges or new dependency needed.

```bash
ctest --preset linux-release -R '^knetsentry_detection_contract$' --verbose --no-tests=error
```

Production store identity integration, rule format/import, authenticated rule
administration, correlation, alert lifecycle, resource budgets across events,
suppression, deployment and response remain future work. M6.10 persistent
volume identity and operational integration (#148) remain outstanding.

M7.2 adds a [versioned rule schema](RULE_SCHEMA_M72.md) for new schema-aware callers.

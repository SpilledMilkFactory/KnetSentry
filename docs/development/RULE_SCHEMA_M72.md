<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M7.2 — Detection-rule schema and validation

Issue #61. Typed C++ schema version 1, not a file serialization or import format.
The [M7.1 engine](DETECTION_ENGINE_M71.md) remains independent of Qt and AI.

## Schema and supported vocabulary

`RuleDefinition` in `knetsentry/detection/rule_schema.hpp` requires:

| Field | Constraint |
| --- | --- |
| schema_version | Exactly 1 |
| ocsf_version | Exactly 1.4.0 (aligned subset) |
| mapping_revision | Exactly 1 |
| predicate.id | 1–64 lowercase ASCII letters, digits, dots, underscores, hyphens; unique in set |
| predicate.version | Nonzero uint32; independent of schema version |
| title | 1–96 printable ASCII bytes, no leading/trailing spaces |
| description | 1–512 printable ASCII bytes, no leading/trailing spaces |
| severity | Informational, Low, Medium, High or Critical; not event severity |
| source_mode | Authentication only |
| predicate.source_unit | Empty (any supported authentication unit) or exact supported unit, at most 128 bytes |
| predicate.activity | Optional Logon or Logoff |
| predicate.outcome | Optional Success or Failure |

At least one activity/outcome predicate is required. Predicates are conjunctive.
Unknown values, unsupported source modes, wildcard sources and conditions with
no definite match under mapping revision 1 are refused. For example, Logoff
with Success is unreachable; current logoff observations have unknown outcome.
A success predicate on login.service is also unreachable. This is a schema
validation rule, not an assertion about real-world login behavior. No new
normalization mappings are invented. Text is ASCII-only initially, and is data,
not executable content; future UI must render it as plain text. Rule metadata
may be sensitive and must not be automatically published.

## Validation and compilation

`ValidatedRuleSet::compile(span<const RuleDefinition>)` refuses more than 64
rules before traversing the input. For each rule, the first invalid field in
schema/version, metadata, source mode, predicate and reachability order is
reported, plus a duplicate-ID diagnostic for each later duplicate valid ID.
A duplicate is invalid even with a different rule version. Diagnostics are in
input order; they carry the original zero-based rule index (or no index for a
set-wide error), a typed error code and static field/action strings returned by
`describe`. Untrusted identifiers, metadata, paths or other input bytes are not
echoed. Correct the reported field and revalidate to reveal subsequent issues.
At most 128 diagnostics are produced for a 64-rule input; an oversized set has
one diagnostic. No invalid rule is silently dropped. Successful compilation
owns the sorted definitions and engine, exposed only through const accessors.
The input may be destroyed or modified after compilation. An empty set is
valid and the engine returns NoRules for eligible evidence. Allocation failures
propagate; callers must not treat them as a successful empty result.

The M7.1 trusted low-level Engine::create continues to accept predicate-only
rules, using the shared predicate validator. New schema-aware callers should
use ValidatedRuleSet::compile, which imposes metadata, version and reachability
constraints in addition to low-level predicate validation. No operational caller
is installed. The schema does not authenticate rule authors, authorize source
collection, establish coverage, prove event truth or grant response authority.
Rule severity remains metadata; the event and finding contracts are unchanged.
The caller must retain the rule definition/version and evidence store identity
for future alert persistence. Version history and anti-rollback are not enforced.
No serialization parser, rule administration, signing, persistence, rule pack,
correlation, scheduler, alert creation or execution of rule text is introduced.

## Qualification

The mandatory `knetsentry_rule_schema_contract` covers schema/OCSF/mapping
versions, bounded metadata, invalid predicates, unsupported sources, unreachable
conditions, duplicate IDs, diagnostic position and action, atomic compilation,
owned metadata, deterministic ordering and actual reference-store composition,
trust preservation, unchanged evidence severity, empty set and 64/65 limits.
Existing M7.1 regressions remain mandatory. All fixtures are synthetic.

```bash
ctest --preset linux-release -R '^knetsentry_(rule_schema_contract|detection_contract)$' --verbose --no-tests=error
```

Target Ubuntu qualification pending. No new dependency, service, GUI or
operational monitoring permission is introduced.

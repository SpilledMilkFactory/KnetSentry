<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M6.6 — Event search and filtering

Issue #56. Development implementation; target-host qualification pending.

## Typed query contract

Both EventStore implementations accept the same SearchQuery, validate it using
one shared predicate, and return owned EventSummary results. Only published
normalized events are visible. All supplied predicates are conjunctive (AND):

- Inclusive normalized source-time interval in milliseconds (`from_ms`,
  `through_ms`), independent of receiver time.
- Exact configured 96-character destination binding; empty means no binding
  filter, not an authorization grant.
- Exact source unit (`audit` or a valid literal journal service name, up to 128
  characters) and optional supported collection mode. No wildcard, substring,
  arbitrary SQL, or raw-payload search.
- OCSF-aligned class, category (Unknown 0 or Identity & Access Management 3),
  activity, outcome, and mapping disposition. Category is derived from the
  pinned normalized class, not from the collector type. A redacted or unmapped
  record remains Unknown/Base; source filters may still select its collector.
- Exact severity: Unknown 0, Informational 1, Low 2, Medium 3, High 4, Critical 5,
  Fatal 6, Other 99. Mapping revision 1 emits Unknown exclusively; known nonzero
  severity queries return an empty successful page, not a guessed severity.
  Adding assigned severity requires a deliberate normalization/schema update.

Omitted optional predicates are not equivalent to explicit Unknown. Conflicting
valid predicates yield no matches; unsupported modes, invalid source/binding,
reversed time, or limits outside 1–32 yield Invalid. Query string views must
remain valid for the synchronous call. Summary results expose ID, source and
receiver time, class/activity/status/mapping, category, severity, source unit
and mode, but not original payload, binding, cursor or integrity digest.

Results are in ascending storage ID order (not chronological order), with
at most 32 entries and a `more` flag set only when another matching row exists.
For continuation use the last returned ID, the returned revision and unchanged
predicates on the same backend. Mutation invalidates the revision (Stale);
no partial page is returned on error. The caller must not repurpose revision
or ID as an authorization token. Cursor binding to query and authorization,
query budgets across callers and a manager/GUI query service remain future work.

## Indexed storage and integrity

SQLite schema v4 adds partial indexes `event_mode(mode,id)`,
`event_source(unit,mode,id)` and `event_time(time_ms,id)` on published rows.
Existing class/status, binding and retention indexes remain unchanged. The
query uses fixed SQL fragments, bound numeric/text parameters, ID ordering and
LIMIT page size + 1. Each returned candidate is independently checked against
canonical normalization and the shared predicate. Category uses the canonical
class column, and severity uses the pinned Unknown-only mapping (no redundant
severity column). The query planner may choose an index or a bounded scan;
representative source/mode/time plans are tested, not every possible plan.

Migration from v3 verifies the exact old schema and all existing digests before
transactionally creating the three indexes; no original evidence, commitment,
origin, hold or revision is rewritten. Fresh databases reach v4. Legacy v1/v2
still require explicit EstablishBaseline authorization, and corrupt v3 or
unknown schemas remain rejected. Activation rechecks version and schema within
the transaction. All valid SQLite queries verify the entire bounded evidence
set within the transaction before returning a page, including impossible
severity queries. This preserves M6.5 tamper detection outside a filter.

The backend remains a bounded development store (128 retained records, 8 MiB
main database limit) with full evidence verification, not a production search
latency or concurrency guarantee. No new dependencies, network authority,
manager query service, GUI evidence access, or ACK integration are introduced.
Production independent raw/index volume activation and authorization remain open.

## Qualification

`knetsentry_event_search_contract` exercises both backends against explicit
known IDs, mixed sources, categories, statuses, activities, redaction,
Unknown-only severity, inclusive timestamp bounds, contradictory predicates,
pending evidence, filtered pagination, 32-row page bound, stale continuation,
invalid inputs, v3 migration without digest replacement, representative query
plans and integrity failure even for filters that cannot match. Synthetic
private disposable databases only; never publish real source names or evidence.
The existing M6.2–M6.5 regressions remain mandatory.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M7.3 — Foundational authentication detections

Issue #62. Offline snapshot evaluation in KnetSentry::Detection, independent of
Qt, AI, manager scheduling and alert persistence. The caller selects an authorized
EventStore, its identity, the full configured endpoint binding and one exact
supported authentication unit, and establishes evidence trust and coverage.
The store is a trusted implementation of the existing search contract, not an
untrusted remote service. A binding selector is not itself authorization.

## Detection contract

`detect_authentication` uses M7.2 schema-validated single-event predicates.
Predicates unreachable on the selected source are explicitly excluded; unexpected
validation failures refuse the scan. Only classified definite Logon/Failure
observations count toward the sequence. The default threshold is five, window
300000 ms; explicit policies allow 2–16 failures and 1–600000 ms. The output
retains policy, snapshot revision, caller coverage, observation and indeterminate
counts, ordered findings, pattern identity/version, rule severity and supporting
store-scoped evidence IDs. The caller must retain store identity and scope.

| Pattern | Trigger | Severity |
| --- | --- | --- |
| RepeatedFailures | Threshold crossing within inclusive rolling receiver window | Medium |
| SuccessAfterFailures | Definite logon success strictly later than the latest failure, with threshold still in window | High |
| UnspecifiedActivityFailure | Classified known failure with unknown activity | Low |
| InvalidUserObservation | Classified unknown activity and outcome (mapping revision 1 uniquely identifies SSH invalid-user) | Low |

Admission ID order and trusted receiver milliseconds define the window, not
endpoint event chronology. Delayed or batched delivery can change interpretation.
Equal receiver timestamps count as separate observations, but cannot establish
strictly later success. A backward receiver timestamp refuses the whole scan.
Only the latest threshold failures are kept; threshold crossings are emitted once
until expiration or a sequence reset. Success resets the sequence; all other
observations (including unknown, redacted, invalid-user without known outcome,
and logoff) reset it as well. The unspecified-activity failure is a separate
observation, not a definite logon failure. Invalid-user is a preauthentication
observation, not a completed attempt; its exact classified mapping is pinned
to revision 1 and must be requalified if that mapping changes. Unknown/unsupported observations are
counted as indeterminate. An unsupported source may have no reachable predicates.

The scan uses ascending revision-bound search pages (32 records, at most four
pages under the 128-record store ceiling). It refuses non-increasing IDs, wrong
source/mode, invalid summaries, clock regression, oversized/malformed pages,
changed revisions, backend errors and any pending index entry in the store.
The latter is intentionally conservative, including unrelated pending records.
No partial findings survive refusal. Unverified trust is refused before IO.
No raw records are read by the scanner; no username, IP, cursor or binding is
included in findings. Up to 128 findings, each at most 17 evidence IDs. No
persistent history or implicit deletion; repeated scans may repeat findings.
Allocation failures propagate and must not become successful empty reports.

## Limitations

A result describes stored observations only, not an attacker, account, attack
origin, compromised endpoint, verified source chronology or confirmed incident.
Different accounts on the same scope can produce a sequence. Missing or deleted
records and incomplete coverage can hide intervening activity; a successful scan
is not proof of completeness or safety. No new collection fields, automatic rule
activation in the manager, response authority or persistent alert/deduplication
are introduced. Rule severity does not alter original event severity.

## Qualification

`knetsentry_authentication_patterns_contract` exercises actual reference store
admission and normalization, scope isolation, window boundaries, evidence IDs,
unknown barriers, pending indexes, clock regression, ties, capacity and
cross-page sequences. Synthetic evidence only. Target Ubuntu qualification passed: 143 consolidated gates, 498 configured CTests, nine hosted checks and reported manual GUI review and merge.

```bash
ctest --preset linux-release -R '^knetsentry_authentication_patterns_contract$' --verbose --no-tests=error
```

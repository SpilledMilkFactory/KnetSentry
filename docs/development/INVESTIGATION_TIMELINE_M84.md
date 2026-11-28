<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M8.4 — Security investigation timeline

Issue #72. Candidate pending target qualification. Read-only investigation of
existing bounded stored pages; no incident mutation, asset inference or live
monitoring. The Investigations section requests the latest eight event IDs
(descending admission order) and the first eight alerts on explicit refresh.
Both authenticated responses must be available and share the manager session;
otherwise no timeline is shown. This is not an atomic cross-store transaction.
No automatic pagination or evidence requests occur.

## Chronology and provenance

Events are ordered by receiver timestamp and alerts by creation timestamp,
ascending unsigned 64-bit Unix milliseconds, then generation (zero for event),
then stored ID. Source time and receiver time are shown separately for events;
creation and update times are shown separately for alerts. These time domains
have different semantics and no causal ordering is inferred. Admission ordering
and chronological ordering differ. Page completeness remains explicit.

Selection exposes normalized metadata only. Related records on the returned
pages are navigable using explicit alert evidence IDs and matching authentication collector and source unit
within the same manager session; this is a stored reference, not a verified
causal or asset link. The protocol exposes source units but no verified asset
identity, so asset attribution remains unavailable. No correlation by time,
unit name alone, hostname or registry proximity. Evidence outside the returned
page can be verified explicitly via the existing read-only ALERTS Evidence
operation bound to the selected alert generation, trigger, revision, evidence
ID and manager session. Manager validation checks the original integrity
commitment and provenance; the result includes source/receiver time, outcome and
integrity origin, never raw content. A stale or refused verification clears the
snapshot. Selection and related-record navigation issue no queries.

## Lifecycle and boundaries

The model retains at most 16 records plus bounded evidence references, uses the
existing nonblocking authenticated local IPC client, and clears after 30 seconds
from refresh initiation, on navigation away, detected manager disconnection or
invalid responses. Evidence inspection does not extend expiry. No persistent
investigation state, new privileges, dependencies, IPC operations or audit
exceptions. No alert acknowledgement or evidence mutation is exposed. All
untrusted text labels use plain text. Existing Dashboard, workspace (including
1920 × 1080 windowed default), Event Explorer and Alerts remain independent.
The health protocol cannot identify a rapid manager restart between polls;
manager-session mismatch is checked on refresh and evidence verification.

## Qualification

Native regression covers empty pages, timestamp order and ties, full-width time,
explicit source/ID links, duplicates, invalid shape, denial and session mismatch.
Rendered regression uses the private M7.7 fixture, checks 16 rows, detail,
related-record navigation, off-page evidence verification, denial, navigation
clearing, exact audit counts and evidence database/ledger invariance. No actual
LAN evidence is required. Run `ctest --preset linux-release -R
'^knetsentry_(investigation_timeline_contract|gui_investigation_runtime)$'
--verbose --no-tests=error` (one command). Inspect source/receiver and alert
creation/update values manually, follow a related record, verify an off-page
reference, test disconnection and expiry. All seven presets, strict QML,
manual GUI and hosted CI remain required. Asset mapping, broader chronological
queries, persistent cases and production-scale qualification remain outstanding.

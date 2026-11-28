<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M8.6 — Advanced search and filtering controls

Issue #74. Candidate pending target qualification. Reusable categorical search
presets and session-saved views for existing manager-mediated Events and Alerts
interfaces. Dashboard and Investigations provide explicit cross-view routes.
No operational monitoring or new data authority is enabled.

## Search definitions and feedback

Events supports the existing exact source (empty means any; otherwise a valid
source unit or `audit`), collector, outcome and admission-ID ordering filters.
Presets: all events (lowest ID first), authentication failures, authentication
successes and Audit (highest ID first for the latter three). Applying a preset
clears the source and invalidates the current event page, selection and cursor.
The actual Search button starts a new first-page query. Manual filters remain
available, disabled while a request is pending.

Alerts supports its existing severity filter, with all, medium, high and
critical presets. Applying a preset invalidates the current alert page,
selection, evidence, mutation authority and continuation. Refresh explicitly
starts a first-page query. Invalid severity outside -1..5 is rejected locally;
existing native validation remains authoritative. The existing explicit alert
acknowledgement workflow remains unchanged.

One session-saved categorical definition per interface is owned by the window's
SearchViews object. Save replaces that slot without a query; Restore applies
its fields and clears the current snapshot; Forget removes the saved definition
without querying or changing the draft. The two slots survive navigation but
not application restart. Event source text is deliberately excluded and is
cleared on preset application or restoration. Only bounded collector/outcome
indices, ordering, severity index and saved flags are retained. No disk writes,
query history, session tokens, evidence, record IDs, credentials, endpoints,
permissions or arbitrary expression strings are saved. No workspace schema
change. The operator must explicitly submit after restoring a definition.

Nonempty result feedback identifies whether more matching records are available
or the returned query has reached its end. Existing unavailable, invalid,
stale, integrity-failure and successful empty-result states are retained.
Results are stored snapshots, not live counts or a safety verdict. Neither
admission-ID order nor alert page order establishes chronology. No global
result count or arbitrary full-text search is claimed.

## Cross-view navigation and bounds

Dashboard, Events, Alerts and Investigations expose explicit destination
buttons that use the existing seven-section replacement route. They do not
transfer selected record identities, filters, snapshots, sessions, revision
bindings or authorization. Source views clear through the existing navigation
lifecycle. The destination requires its own explicit authorized query. Timeline
related-record links retain their existing semantics; these new routes are
not evidence correlation or record-specific deep links.

The manager protocol, authorization, audit, evidence integrity and persistence
formats are unchanged. Each returned Events or Alerts page remains limited to
eight records; the existing manager and client enforce request and response
bounds. No automatic query, pagination, background search, raw evidence access,
SQL expression, new network action or privilege. Existing 30-second snapshot
lifetime and invalidation policies remain unchanged. Alert offset pagination
retains the existing separate-request semantics, not an atomic global snapshot.
The existing workspace, motion policy and 1920 × 1080 windowed startup remain.

## Qualification

The existing rendered Events and Alerts integrations exercise actual preset,
save, restore, forget and cross-view handlers, verify categorical values and
source exclusion, explicit query submission, populated-snapshot clearing,
invalid input refusal, and the existing result and pagination assertions.
The Python harnesses check exactly four authorized event requests and five
read-authorized alert requests (four lists and one linked evidence inspection)
during their respective GUI processes; acknowledgement is independently
classified and audited. Existing evidence database invariance remains required.
The tests retain their actual manager and synthetic fixture workflows. No new
CTest registrations. Run the existing native and rendered suites and all seven
presets, strict QML lint and manual GUI testing. Source checks alone do not
qualify Qt compilation or the rendered controls.

Session-only saved views, categorical-only persistence in memory, no alert
lifecycle/source search, no timeline-wide query, no record-specific deep links,
no independently persisted named views, and operational workload qualification
remain limitations. Keep broader issue #74 scope open.

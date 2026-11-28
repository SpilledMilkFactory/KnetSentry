<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M8.1 — Comprehensive SOC dashboard foundation

Issue #69 (P1, GUI feature). Implemented foundation accepted and merged; remaining operational scope open. The SOC overview composes actual existing health, local collection and explicitly authorized stored summaries. No production data is simulated and no new monitoring authority is created.

## Sources and limits

| Card | Source and meaning |
| --- | --- |
| Security status | Monitoring unavailable, posture unknown; no safety verdict. |
| Asset coverage | Verified AGENTS roster counts (approved/revoked identities), not live sessions or monitored assets. |
| Stored event activity | First descending admission-ID page of EVENTS (at most eight); count, failure outcomes and maximum receiver timestamp on that page. Not chronological ordering, event rate or incident count. |
| Active stored alerts | First unfiltered ALERTS page (at most eight); open plus acknowledged, resolved separately, and high/critical active subset. Not total active alerts across a deployment. |
| Stored detection summary | Distinct rule identifier count represented by the same alert page; not active rule count, technique execution or detection coverage. |
| Operational health | Existing HEALTH polling every 30 seconds, including resources and operational counters; existing attached local report stream remains separately labeled. |

Health and local telemetry retain their existing refresh cadence. The stored overview is deliberately operator-requested, not unattended evidence polling. The refresh action uses the explicit IPC directory selected at desktop launch, first a fixed unfiltered descending EVENTS query and then a fixed unfiltered ALERTS list query. It does not request detail, acknowledgement, mutation, additional pages or raw evidence. Queries are nonblocking and reuse the existing same-UID/GID verified transport, request IDs, schema validation, bounds, manager-side opt-in and audit policy. Root requests are disabled. No database, alert ledger, registry, remote feed, or filesystem path is directly opened by the new dashboard. The dashboard does not change the other section models or their selected filters.

Each request cycle clears the previous summaries; a successful empty page differs from a denied, unavailable, invalid or integrity-failed response. A page with more results is explicitly identified as incomplete. If both successful responses identify different manager instances, clear both. These are separate snapshots, not an atomic multi-store transaction. The summaries expire 30 seconds after refresh starts, clear on navigation away, and clear when existing health polling reports disconnection or invalid response. Disconnect discovery is bounded by polling, not instantaneous. The dashboard remains read-only even if the manager offers acknowledgement on the Alerts page. Only aggregate values are shown; no source identifiers or rule names are copied into the overview. No new privilege, dependency, persistence, public intelligence egress, trust boundary or monitoring authorization is introduced.

## Verification

`knetsentry_dashboard_summary_contract` tests bounded pages, empty/unavailable distinctions, receiver maximum, failure counts, active lifecycle, distinct rule IDs, severity, malformed page shape and integrity refusal in all seven presets. `knetsentry_gui_dashboard_runtime` exercises the rendered dashboard through the existing synthetic M7.7 seed, default-denied manager, navigation clearing and byte-for-byte store/ledger invariance; it uses the existing non-sanitized GUI test scope. No additional sanitizer exceptions. The existing GUI health/registry and telemetry regressions remain mandatory. Manual tests must exercise expiry, disconnect and reconnection, compact layout, and existing navigation. The dashboard summary target has no Qt/KDE dependency.

Expected inventories: 86 CTests for Release/Debug/Clazy/analysis, 77 full sanitizer, 70 core-only, 71 sanitized core-only; 562 total; 72 structural verifiers and 157 consolidated gates with all existing privileged fixtures requested. These are target inventories, not qualification evidence.

### M8.1 qualification follow-up

The initial Ubuntu 26.04 analysis build failed in `ServiceHealthModel::dashboardRegistry()` because an ordinary C++ translation string contained a physical newline before its closing quote. The follow-up uses adjacent string literals with an explicit `\n`, retaining the intended two-line text and a single translatable message. The existing Qt health model regression now checks the read-only property and unavailable text before and after an absent-endpoint refresh. The existing GUI health runtime additionally checks the exact one-approved/one-revoked summary from its synthetic registry and unavailable status after disconnect and unconfigured restart. No new CTest registration, privilege, monitoring authority, diagnostic exception or acceptance gate is introduced. Combined commits qualified: 157 consolidated gates, 562 configured CTests, 72 structural verifiers, nine hosted checks and successful manual GUI verification; maintainer reported merge. The manual fixture must use the exact IPC directory printed at creation, not a placeholder.

## Manual synthetic fixture

As a normal user, create a private disposable directory under `/var/tmp` and separate `ipc`, `store`, `scheduler`, `alerts`, and `audit` subdirectories with mode 0700. Run the Release `knetsentry_alert_interface_test --seed` with the store, scheduler and alert directory arguments, then run Release `knetsentryd --ipc-dir ABS --audit-dir ABS --event-store-dir ABS --alert-dir ABS --alert-access read` using those exact fixture paths. Launch Release `knetsentry --ipc-dir ABS` in another terminal. The existing [alert interface guide](ALERT_INTERFACE_M77.md) documents the underlying fixture. Refresh stored summaries: expect eight events and eight failure outcomes, eight active open alerts, one distinct rule identifier; both pages have additional records. All numbers are synthetic fixture data, not live activity. Wait 30 seconds from refresh or leave Dashboard and return: summaries become unavailable. Stop the fixture manager: health eventually reports unavailable; a subsequent refresh must not display fabricated zeros. Restart and explicitly refresh. Exercise narrow and wide window layouts, existing Alerts and Events pages, and clean shutdown. Stop processes before deleting the disposable fixture. Never use private operational telemetry for this qualification.

## Remaining issue scope

Refs #69: actual monitored-asset inventory, network coverage, unattended operational event and detection activity, and deployment-wide alert aggregation remain outstanding. Existing #40/#46/#50/#51/#63/#64/#65/#66/#148 limitations remain. The dashboard does not close those issues or qualify M8 or v1.0.0. No live detection, monitoring or response authority is enabled.

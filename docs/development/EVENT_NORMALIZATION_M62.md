<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M6.2 — OCSF-aligned event normalization

## Scope and version pin

C-12 and the KSTD subset of I-10 now use a typed, Qt-independent normalizer in
`KnetSentry::AgentDelivery`. The internal projection is pinned to **OCSF 1.4.0**
and KnetSentry mapping revision 1. The pin is an explicit conservative baseline,
not a claim that this is the latest upstream release. References: the upstream
[v1.4.0 version](https://github.com/ocsf/ocsf-schema/blob/v1.4.0/version.json),
[base event](https://github.com/ocsf/ocsf-schema/blob/v1.4.0/events/base_event.json),
[authentication](https://github.com/ocsf/ocsf-schema/blob/v1.4.0/events/iam/authentication.json),
[categories](https://github.com/ocsf/ocsf-schema/blob/v1.4.0/categories.json), and
[dictionary](https://github.com/ocsf/ocsf-schema/blob/v1.4.0/dictionary.json).
No upstream schema files, generated source, or new dependencies are bundled.
No network lookup occurs at runtime. Future schema upgrades require explicit
mapping revision review and replay/regression qualification.

This is an **OCSF-aligned internal projection**, not a complete OCSF event or a
validated OCSF JSON export. Authentication requires user information in OCSF;
our minimized inputs do not provide it. We do not invent users, addresses,
severity, session identifiers or authentication factors. Metadata/product and
other full serialization requirements remain future export responsibilities.

## Inputs and outputs

`normalize_event(canonical_row, configured_binding, unit, mode)` returns
`std::optional<NormalizedEvent>`. The caller must establish authority and select
binding and source independently of peer data. The function performs no
identity authentication, enrollment approval, network authorization or I/O.
The shared `parse_delivery_row` uses the original canonical validator's
bounds, exact source/profile checks and canonical round trip. Invalid input
returns no result. Allocation failure propagates; receiver failure handling
prevents an acknowledgment. A valid but unmapped observation is not invalid.

The value owns the exact bounded canonical KSTD row (at most 2048 bytes),
parsed native `JournalRecord`, configured 96-character destination binding,
source mode, OCSF classification fields, and explicit `MappingResult`. The
binding identifies the configured enrolled endpoint and manager fingerprint;
it is not a credential or a source-reported machine ID. The native machine,
boot, cursor, unit and timestamps remain untrusted source assertions. The
retained canonical row is already minimized collection evidence, not a raw
journal message or a cryptographic integrity proof. It and its identifiers are
sensitive and must not be logged or included in public artifacts.

## Mapping revision 1

The OCSF class/category/type numbers are Base Event 0/0/0 and Authentication
3002/3 with type UID computed as class UID times 100 plus activity ID. All
severity IDs are Unknown (0): no source severity is available. Status IDs are
Unknown (0), Success (1) or Failure (2). Classification is source-reported,
not an independent verification or detection.

| Native profile/category | Class | Activity ID | Status ID | Mapping result |
| --- | --- | --- | --- | --- |
| Journal metadata | Base | 0 | 0 | MetadataOnly |
| Linux Audit (numeric type/id only) | Base | 0 | 0 | AuditTypeUnmapped |
| ssh-accepted | Authentication | 1 | 1 | Classified |
| ssh-failed, login-failed | Authentication | 1 | 2 | Classified |
| authentication-failed | Authentication | 0 | 2 | Classified |
| ssh-invalid-user | Authentication | 0 | 0 | Classified |
| session-opened, login-session-created | Authentication | 1 | 0 | Classified |
| session-closed, login-session-removed | Authentication | 2 | 0 | Classified |
| redacted | Base | 0 | 0 | Redacted |
| unclassified | Base | 0 | 0 | Unclassified |

Classified means a supported class mapping, not complete activity/status
knowledge. An invalid-user observation is not necessarily a completed logon
attempt. Session lifecycle observations do not establish an authentication
outcome. Numeric audit type/id alone do not establish a specific activity or
result; preserve them without inventing process, file or user attributes.
Redacted and unclassified inputs stay distinct, with no category reconstruction.
FIM and generic sensor/gateway envelopes are outside this subset.

## Timestamp and durable receipt boundary

`time_ms` is integer floor division of source journal realtime microseconds by
1000. The exact source realtime and boot-relative monotonic microseconds are
retained separately. Submillisecond times may map to zero; this is a valid
converted epoch value, not a missing timestamp. No clock correction, clock
trust, manager-arrival timestamp or processing timestamp is inferred. Journal
realtime describes the source journal observation, not necessarily occurrence
of the underlying activity. Boot-relative monotonic time is not an epoch.

The authorized receiver validates the binding, normalizes before the existing
sink invocation, and retains one normalized result only after durable sink
acceptance. The result is exposed by a read-only borrowed accessor
`DeliveryReceiver::normalized_event()` for the receiver lifetime. A nonthrowing
move publishes it after commitment without allocation. Invalid, unauthorized,
overloaded or sink-rejected input does not establish a result. If durable
commitment precedes a later ACK failure or revocation, the accepted result is
still available; it does not imply ACK success or sender receipt. Exact retry
can reproduce a result without creating a second durable record.

The sink still persists the original canonical row, not the normalized result.
No new persistent format, raw message repository, normalized index, retention,
operational manager listener, schema export or GUI event publication is added.
One bounded typed value per receiver is retained until destruction; callers
must continue to enforce overall receiver lifetimes and aggregate budgets.
No cross-thread safety or new privileges are introduced.

## Qualification

`knetsentry_event_normalization_contract` is mandatory in all seven presets.
Synthetic cases cover all authentication categories, metadata/audit fallback,
version and numeric IDs, original ownership and precision, redaction,
source/profile rejection, malformed integers and bounded timestamp values,
invalid bindings, control characters, missing framing and oversized rows.
The existing authenticated ingestion and delivery tests additionally verify
normalized results after durable commitment, absence on rejection and
preservation of original evidence. No host telemetry is required.

Target: desktop 62/56, core-only 49/50 (normal/sanitized), 403 total CTest
executions, 54 structural verifiers and 119 consolidated acceptance gates.
Target-host qualification is pending. This contributes partial TB-06/TB-07,
TH-015 and TV-10/TV-25 evidence; no threat closure is claimed. Full generic
I-10, normalized persistence, schema export/validation, receiver-side privacy
administration and operational manager integration remain outstanding.

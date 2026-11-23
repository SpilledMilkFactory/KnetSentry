<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry — Logical Interface and Data Contracts

**Issue:** M0.4. **State:** architecture proposals; interfaces are not yet
implemented. See [components](COMPONENT_CATALOG.md),
[system architecture](SYSTEM_ARCHITECTURE.md) and
[network requirements](../security/NETWORK_SCOPE_REQUIREMENTS.md).

## 1. Cross-interface mandatory rules

1. Every cross-process request MUST have an explicit interface version,
   message-size/collection-count limits, deadline/cancellation behavior,
   meaningful error category, and audit/metrics decision before implementation.
2. **Authentication and authenticity are different:** a valid TLS peer or Unix
   peer credential authenticates a channel principal, not the truth of an event
   field or the firmware identity of an IoT device. Preserve `SourceTrustClass`
   and evidence provenance throughout the system.
3. There are **separate authorizations** for sensor observation scope, agent
   transport, provider egress, and local operator/response permissions.
   No event, AI model, or public feed may silently create one of these grants.
4. Producer overload MUST cause bounded backpressure, explicit drop/quarantine
   accounting, or a documented failure; never unbounded allocation or silent
   fabrication of clean coverage. Replays/duplicates must use stable source-
   scoped identities and documented idempotence semantics.
5. Preserve event time, acquisition time, and receive time separately, along
   with source identity, approved scope, drop counts where measurable, and
   attribution uncertainty. A missing field remains unknown.
6. Privilege escalation and egress require independent OS enforcement, not
   only a boolean returned by a manager function. Validate actual enforcement
   after policy application; errors deny the affected operation.
7. Audit excludes raw secrets and private payloads by default. Payload/packet
   retention and incident export require separate access and retention policy.

## 2. Interface registry

The `I-##` identifiers describe **logical interface contracts**. Endpoints and
serialization are not frozen yet; implementation owners must pin encoding,
version policy and supported error codes before exposing a socket or stable ABI.

| Interface | Producer -> consumer | Essential payload and trust treatment | Authorization / failure behavior | Milestone |
| --- | --- | --- | --- | --- |
| `I-01` | Qt/CLI -> manager | `LocalRequest{version,principal,action,params,request_id}`; Unix peer credentials plus operation role | Default deny for non-authorized action; no remote admin listener | M2.3 |
| `I-02` | Manager policy -> policy applicator | `PolicyProposal{generation,approved_scope,digest,actor,evidence}` | Explicit authorized change; stage/verify/activate or rollback; never event-triggered | M3.5 |
| `I-03` | Capture broker -> sensor worker | Bounded frame data/metadata, interface/scope, original-length, truncation, loss counters | Only approved capture scope; parser unprivileged; drop accounting | M5.10 |
| `I-04` | Sensor worker -> ingest | `SourceEnvelope` with observation scope, source/clock/coverage, event shape, trust class | Approved local pipe or authenticated remote relay; reject scope violations | M5.10/M6.1 |
| `I-05` | Gateway device/export -> adapter | External syslog/flow/DHCP/DNS/AP record plus sender metadata | Approved source; sender may be spoofed; trust explicitly marked | M5.10/M9.4 |
| `I-06` | Gateway adapter -> ingest | Provenance-tagged `SourceEnvelope`, parse/confidence errors | Local channel with restricted process identity; bounded input | M5.10/M6.1 |
| `I-07` | Enrolled host agent -> receiver | Versioned authenticated telemetry and heartbeat envelope | mTLS, enrollment, revocation, scope checks, length/rate limits | M4.3–M5.5 |
| `I-08` | Receiver -> manager ingest | Verified peer fingerprint, enrollment/scopes + separately untrusted reported fields | Verify source binding, no admin commands, bounded queue | M4.3/M6.1 |
| `I-09` | Privileged host collector -> optional agent | Narrow authorized OS event records and collection health | Local authenticated IPC; minimal read permission | M5.4 |
| `I-10` | Ingest -> normalizer | `ValidatedSourceEnvelope` and declared parsing/validation status | Reject/quarantine unsupported/schema-bad records; no policy changes | M6.1/M6.2 |
| `I-11` | Normalizer -> storage | `NormalizedEvent` + `EvidenceReference` + original evidence when approved | Transactional manager-only storage write, retention, duplicate behavior | M6.2–M6.5 |
| `I-12` | Storage -> deterministic detection | Bounded event cursor and source/coverage trust metadata | Query limits; rules cannot alter original stored evidence | M7.1 |
| `I-13` | Detection -> alert/case storage | `Finding{rule_id,version,evidence_ids,uncertainty}` | Persist separately from immutable-original strategy; no response authority | M7.6/M11.1 |
| `I-14` | Ingest/storage -> asset/coverage intelligence | Asset observations, scoped device hints, drop/capability state | Tentative ID and confidence; IP/MAC alone never verified identity | M9.1/M9.2 |
| `I-15` | Manager -> feed worker | `ApprovedFeedRequest{provider_id,feed_id,policy_generation}`; no arbitrary event URL | Provider opt-in and allowed operations; default deny, audit query privacy | M3.9/M10.9 |
| `I-16` | Feed worker -> approved public provider | Bounded TLS HTTPS request, only approved endpoint/path/redirect policy | DNS/connected-peer checks, TLS validation, host firewall egress | M3.9/M10.9 |
| `I-17` | Feed worker -> manager | Bounded feed bytes + origin/version/freshness metadata, no direct DB writes | Untrusted parser, provenance checks, quarantine and atomic cache promotion | M10.9 |
| `I-18` | Manager -> isolated AI worker | Minimized, pre-authorized evidence context + bounded result | No network, file access or tools beyond approved IPC; timeout/fail independently | M12.2–M12.9 |
| `I-19` | Incident gate -> policy applicator | `ApprovedResponse{actor,scope,action,expiry,audit_ref}` | Disabled by default, explicit human approval, narrow operation; verify outcome | M11.5 |
| `I-20` | Case service -> authorized export | Incident evidence references, redaction/export policy, audit record | Role-checked, safe output destination, review before disclosure | M11.6 |
| `I-21` | Components -> audit/health | Category-coded operation outcome, backlog/drops, no secrets | Privilege-aware redaction and bounded retention; fail/report audit gaps | M1.6/M2.5 |
| `I-22` | Remote authorized sensor -> receiver | Sensor-scoped signed/mTLS identity + approved sensor events | Separate enrollment profile from host agents, bounded and scope-bound | M4/M5.10 |
| `I-23` | Manager authorized query -> Qt C++ models/QML | Typed paginated `Asset/Event/Alert/Case` read models and state updates | `I-01` authorization; no direct DB/privileged operations | M1.4/M6.8/M8 |

## 3. Source evidence envelope: semantic sketch

```text
SourceEnvelope v1 (logical fields, NOT a wire encoding)
  source_id: stable configured source identifier
  source_kind: passive_capture | gateway_export | host_agent | remote_sensor
  transport_identity: authenticated principal OR unauthenticated/unknown
  observation_scope_id: approved scope reference
  observed_local_asset: optional tentative identifier and evidence
  observed_remote_peer: optional untrusted network endpoint
  source_event_id: optional source-local deduplication key
  source_event_time: optional with declared clock/uncertainty
  acquisition_time: when collector acquired available record
  manager_receive_time: set by manager on receipt, never trusted from source
  source_trust_class: cryptographically_authenticated | configured_but_unverified | unknown
  attribution_confidence: unknown | low | medium | high (not proof)
  coverage: observed | partial | unavailable | unknown + drop counters when measurable
  data_classification: metadata | allowed_raw_event | allowed_packet_payload
  evidence_data: bounded source bytes / typed fields under approved collection policy
  schema_version / content_type / limits / validation_result
```

This is a required information model, not an instruction to retain private
packet payloads. `cryptographically_authenticated` authenticates the submitting
principal only. External IPs in source evidence must never become implicit
requests to `I-16`. Untrusted event text may contain hyperlinks, shell code,
model instructions, credential strings, and fake timestamps: all remain data.

**Disposition:** `accepted`, `rejected`, `quarantined` or `degraded` with a
reason (e.g. `scope_denied`, `oversize`, `unsupported_version`,
`source_unverified`, `queue_full`, `parse_error`). Exact enum names and
limits will be finalized with versioned protocol schemas in M4–M6.

## 4. Failures and recovery by boundary

| Failure | Mandatory architectural response |
| --- | --- |
| Unknown local network source | Do not grant management authority; ingest only if policy permits passive/source observation, with reduced trust or rejection |
| Sensor lacks network visibility | Report unavailable/partial coverage; never show "all devices safe" |
| Invalid agent certificate or scope | Reject session before accepting trusted telemetry; preserve bounded security audit |
| Unexpected route or firewall divergence | Deny affected connection/operation until policy is independently verified |
| Unsupported event type or out-of-budget payload | Reject/quarantine; count and expose losses; avoid crashes or unlimited retries |
| Storage unavailable or full | Bounded buffer/retention, prominent degraded state, documented recovery; no fictitious events |
| Approved feed down or invalid | Keep last validated cache with staleness visible; core SIEM continues |
| AI model missing or unsafe | Disable/degrade AI only; deterministic detection and cases unaffected |
| Operator or response unauthorized | Reject and audit; do not accept rule/AI/feed text as operator approval |
| Capture broker crashes | Sensor marks source unavailable; restarts only through approved service policy; no silent scope expansion |

## 5. Implementation and compatibility governance

The initial ABI/wire protocol, file formats, max sizes, TLS stack, mTLS
certificate profile, migration strategy, IPC socket paths, OS sandbox profile
and error catalog are **open** until their owning milestone implements and
tests them. Version negotiation and compatibility behavior must be explicit,
never implicit fallback to an insecure or unvalidated mode.

Any interface revision crossing `TB-01`–`TB-12` requires reviewing the threat
register and its verification matrix, with an explicit regression test owner.

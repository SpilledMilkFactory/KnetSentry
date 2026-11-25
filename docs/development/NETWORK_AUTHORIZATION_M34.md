<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M3.4 — Fail-closed network authorization

**Scope:** issue #29; in-memory agent transport preflight only. Advances C-02,
TB-11, KS-NET-014/015/026/027/029/030, TH-012/013 and TV-09. This is not
complete requirement closure or a deployed firewall/transport qualification.

`NetworkAuthorization` composes the existing `NetworkScopePolicy` and
`LinuxTopology` in a single owner-thread-only object. It owns the compiled
policy, administrative interface bindings and observation epoch. The pure
policy and topology adapters remain lower-level primitives for tests and
implementation; future operational callers must not use them as standalone
connection permits or bypass this activation lifecycle. No production IP
transport caller exists today. The dedicated manager remains lifecycle-only.

## Activation and withdrawal

Only a trusted local administrative/configuration publisher may invoke
`activate` or `disable`. `ConfigurationEvidence::Validated` is an assertion
from that publisher, not a validation of a file, user credential or signature.
There is no persistent network-policy format, runtime file watcher, approval
UI or audit publisher in this issue. Future publishers must authenticate and
validate inputs before marking them validated and call disable promptly when
configuration is lost/withdrawn. Safe defaults never create network approvals.

Every activation attempt clears previous authority first. Nonzero revisions
must strictly increase for the lifetime of the object. A fresh revision is
consumed even when activation fails. A stale or zero revision closes the gate
without lowering the high-water mark. There is no rollback to an old positive
policy; a reviewed rollback of content must be published as a new revision.
Exhaustion at UINT64_MAX cannot wrap. This is not restart-persistent replay
protection: generation storage and administrative activation authorization
must be established before operational transport is enabled.

Only schema 1 (exact) or schema 2 (exact plus prefixes) is accepted, using
M3.1/M3.2 validation. Empty policy explicitly closes the gate. Each referenced
interface index requires exactly one unique administrator-approved name;
missing, duplicate or unused bindings reject the entire activation. Names
must be 1–15 ASCII letters/digits/dots/underscores/hyphens (not `.` or `..`).
No caller-owned string view is retained. The bound of 64 applies to the
combined approvals and to the binding table. The trusted publisher is
responsible for revalidating attachment identity before issuing new revisions;
name/index alone do not prove physical attachment identity.

## State and evaluation contract

| State | Meaning / recovery |
| --- | --- |
| Unconfigured / Disabled | Deny until explicitly activated with a newer revision. |
| ConfigurationUnavailable / InvalidConfiguration | No valid administrative configuration evidence; deny. |
| StaleGeneration | Invalid activation revision; retain high-water mark; deny. |
| InvalidPolicy / EmptyPolicy / InvalidBindings | No usable compiled approvals; deny. |
| TopologyUnavailable / TopologyInvalidated | Observation acquisition failed or a change/loss was detected; deny. |
| RouteUnverified | An eligible candidate could not establish the required live route/link evidence; close the gate. |
| Ready | Valid configuration, bindings and observation mechanism; **not** evidence of any authorized destination or live transport. |

All closed states require explicit newer activation. No automatic retries,
last-known-good policy, default route fallback, or cached permission exists.
`check_changes()` polls without blocking; `evaluate()` calls it before
inspection and the existing topology adapter rechecks after kernel queries.
The evaluator requires the expected active generation and obtains the expected
interface name from owned administrative bindings, not from a proposal.
Caller route evidence is ignored by LinuxTopology. A stale request denies
that request rather than withdrawing an otherwise current policy. A denied
purpose, endpoint or approval similarly denies the operation without closing
the entire gate. An eligible route/link verification failure conservatively
closes the whole agent preflight object; this availability trade-off is
intentional until finer-grained revocation is implemented. Do not expose
activation or arbitrary evaluation to unauthenticated callers.

`AuthorizationResult::candidate_in_scope()` requires exactly Ready, a nonzero
revision and CandidateInScope. Unknown state/decision values are negative.
The return is a bounded decision/status snapshot, not a capability or reusable
permit. No IP socket opens, no packet is sent, and no raw addresses/names are
printed. Do not cache or use a previously returned positive result after
configuration or topology changes. Offline functions, local IPC and separately
authorized passive observation/intelligence policies are not changed.

## Verification and remaining limitations

Run `python3 scripts/verify_m34_network_authorization.py --build-dir
build/presets/linux-release` (one command). The compiled regression tests
activation/withdrawal, missing/invalid configuration, stale requests and
revisions, exhaustion, invalid/empty policies, binding coverage/ambiguity,
ordinary denials, real loopback rejection despite forged route evidence, and
unavailable topology acquisition using a process-local descriptor limit.
The full 256-by-256 state/decision classification matrix is exercised. The
optional M3.3 namespace watcher also checks M3.4 gate invalidation and stale
recovery after real kernel notifications. No host route or interface changes
are required for mandatory testing. Keep host security restrictions intact;
optional namespace setup denials are BLOCKED, not PASS.

The gate is not thread-safe and must be accessed/destroyed by its owner thread;
future event-loop integration must call check_changes and revoke existing
sessions. No session management, persistent revision authority, trusted
configuration loader, physical attachment qualification, authenticated endpoint
identity, socket binding or independent OS enforcement is implemented. The
existing topology check/use race remains. Positive classification fixtures
are not positive physical-interface transport qualification. Do not enable
IP transport until the remaining authorization and enforcement prerequisites
have been implemented and verified.

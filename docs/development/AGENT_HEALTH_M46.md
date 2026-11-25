<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M4.6 — Secure agent heartbeat and health reporting

This is an offline reusable foundation, not a deployed agent or network listener.
`KnetSentry::AgentHealth` composes the [KSAP codec](AGENT_PROTOCOL_M41.md),
[mutual TLS](TLS_TRANSPORT_M43.md), [explicit enrollment](ENDPOINT_ENROLLMENT_M44.md)
and [credential lifecycle](CREDENTIAL_LIFECYCLE_M45.md). The wire protocol stays
KSAP 1.0; no additional message types, permissions or dependencies are introduced.

## Reporting and admission

`agent_health::Reporter` is bound to one established agent-side TLS session.
It revalidates the caller's independently approved current manager pin before
sending. It emits HELLO with sequence 1, an immediately eligible first HEARTBEAT
with sequence 2, and subsequent heartbeats at least 30 seconds apart (after a
successful send). A `WouldBlock` retains the identical encoded frame for retry;
sequence and reported counter state advance only after a complete TLS write.
The caller must drive TLS ciphertext and supply its own measured uptime and
cumulative dropped-record count. Counter regressions at send time and clock
regressions abort the session. Reconnect creates a new reporter and TLS session.
No heartbeat delivery acknowledgement is defined.

`agent_health::Tracker` is bound to one trusted endpoint ID and a duplicate of
the administrator-selected registry directory descriptor. It owns one currently
trusted manager-side TLS session and has no plaintext injection method. Admission
and every ciphertext input/output and poll require current enrollment revalidation.
A competing connection cannot replace an existing valid session. Each poll reads
at most 4096 plaintext bytes from TLS; a fixed 36-byte accumulator handles
fragmented headers/bodies and coalesced frames using `inspect_header` and
`SessionValidator`. Invalid lengths, types, ordering, sequences and regressing
counters terminate the session and erase the current snapshot. No partial frame
or HELLO alone constitutes a heartbeat. Current admission is checked again
before returning any newly consumed report. TLS validity checks remain active.

| State | Meaning |
| --- | --- |
| Missing | No current session, explicit transport loss, clean close, or report deadline elapsed |
| Awaiting | Admitted session but no complete accepted heartbeat yet |
| Healthy | Recent authenticated report with zero reported cumulative dropped records |
| Degraded | Recent authenticated report with nonzero reported cumulative dropped records |
| Untrusted | Current identity/registry/transport/time checks failed |
| ProtocolError | Invalid KSAP framing, sequence or counter progression |

Only Healthy and Degraded carry reported counters. The values are untrusted
agent assertions, not measured manager resource usage, proof of endpoint
integrity or evidence of monitoring coverage. Any nonzero cumulative loss
remains degraded for the connection; restarting the sequence on a fresh TLS
session does not prove that historic loss was resolved. No historic metrics
are stored. A 90-second deadline starts at attachment and is refreshed only
when a complete authenticated heartbeat is consumed. Expiration is checked
before processing queued data; a heartbeat at or after the deadline cannot
resurrect the session. The clock is a trusted caller-supplied local monotonic
millisecond value, not an agent timestamp. Backward values invalidate trust.
Poll even while idle; a scheduler is not included. A delayed but in-deadline
report is timestamped at consumption, not remote creation.

## Bounded reconnect

`agent_health::Reconnect` provides a scheduling gate only. `begin(now)` returns
one attempt token when eligible. `connected(now, token)` and `lost(now, token)`
reject stale completion/loss notifications; attempts time out at 10 seconds.
Failures schedule 1, 2, 4, 8, 16, 32 and then at most 60 seconds between attempts.
After a connection is continuously online for at least 90 seconds, subsequent
loss restores the initial delay. Clock regression and attempt-token exhaustion
block the gate. No delay arithmetic adds to an absolute timestamp; elapsed time
is compared after monotonic validation. No random jitter or finite retry-count
limit is introduced. An operational adapter must cancel timed-out transport
attempts, bound concurrent resources, and report connection success only after
actual authentication; each attempt still requires network authorization.

## Integration and limitations

Use single-threaded objects with one tracker per configured endpoint, a bounded
manager-owned inventory (at most the registry capacity), no duplicate trackers,
and a trusted local clock such as `steady_clock`. Serialize policy mutation and
application processing as required by the operational trust model. The current
registry API does not hold a lock across all application processing; no atomic
revocation-to-processing guarantee or asynchronous notification is claimed.
The reporter borrows its TLS session, which must outlive it; do not bypass the
reporter with arbitrary writes. Adapters own socket lifetime, retry scheduling,
transport deadlines, manager trust updates, network scope enforcement, aggregate
rate limits, jitter, and cancellation. Tracker destruction or terminal state
aborts the owned in-memory TLS session; a future adapter must close its socket.

No new production manager or GUI linkage, TCP listener, operational agent,
monitoring consent, persistent health database, or firewall permissions are
introduced. The manager remains lifecycle-only. Agent health is distinct from
the desktop's existing local manager heartbeat. No private endpoint identifiers,
keys or report payloads are emitted by the regression diagnostics.

## Verification

`knetsentry_agent_health_contract` is mandatory in all seven presets. The
existing ephemeral certificate fixture drives genuine TLS ciphertext through
reporter and tracker; no sockets, external services, privileges or real endpoint
data are required. Tests cover valid and degraded reports, missing deadlines,
HELLO-only state, fragmented/coalesced frames, malformed and replayed sequences,
regressed counters and time, unauthenticated and unknown admission, duplicate
connections, missing manager approval, busy registry, key rotation, buffered
report rejection after revocation, and capped reconnect with stale tokens.
Existing M4.5 expiry tests remain mandatory. This is partial evidence for
I-07/I-08, TB-04, TV-06/TV-07/TV-13; not operational or release qualification.

## M4.7 extension

The [desktop enrollment view](DESKTOP_AGENT_MANAGEMENT_M47.md) explicitly
reports agent health unavailable because the manager does not host live agent
sessions. Registry approval is not a heartbeat or certificate observation.

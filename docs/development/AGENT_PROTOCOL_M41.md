<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M4.1 — Agent communication protocol (KSAP 1.0)

Issue #34; interface `I-07`, trust boundary `TB-04`, threat `TH-008`,
verification objective `TV-07`; relevant requirements `KS-NET-006` and
`KS-NET-011`. This is an offline wire and ordering contract, not a transport,
PKI, enrollment, telemetry ingestion or authorization implementation.

## Wire representation

All offsets are zero-based, all integers unsigned big-endian, and all bytes
must be present. No native structure layout, string, compression, padding,
optional fields or extension flags are supported. The agent sends these frames
only after future authenticated and authorized transport setup; the codec itself
has no I/O or authority. The wire version is independent of the application
version and the existing Unix-domain management IPC version.

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII `KSAP` (4b 53 41 50) |
| 4 | 1 | Major version, exactly 1 |
| 5 | 1 | Minor version, exactly 0 |
| 6 | 1 | Message kind: 1 HELLO, 2 HEARTBEAT |
| 7 | 1 | Reserved flags, exactly zero |
| 8 | 4 | Body length in bytes (not including header) |
| 12 | 8 | Connection-local sequence number, nonzero |

The header is exactly 20 bytes. HELLO has no body, HEARTBEAT has a 16-byte
body, and the complete maximum frame size is 36 bytes. Types 3–255 and 0
are unsupported (no implicit telemetry, enrollment, commands or extensions).
A future explicitly reviewed protocol revision must define any new message
schema, provenance, count limits and compatibility rules before accepting it.

| Message | Body offset | Bytes | Field |
| --- | ---: | ---: | --- |
| HELLO | — | 0 | No payload or claimed identity |
| HEARTBEAT | 0 | 8 | Reported agent process uptime, milliseconds |
| HEARTBEAT | 8 | 8 | Reported cumulative records dropped during the agent process lifetime |

Both heartbeat counters may be zero and may saturate at UINT64_MAX; they
must not decrease within one connection. A process restart requires a new
connection. These are untrusted reported values, not coverage evidence, a
manager receive timestamp, a trusted event record or proof of agent identity.
No operational heartbeat is generated or consumed in M4.1.

Canonical HELLO sequence 1 (hexadecimal):

```text
4b 53 41 50 01 00 01 00 00 00 00 00 00 00 00 00 00 00 00 01
```

Canonical HEARTBEAT sequence 2, uptime 1 and dropped records 0:

```text
4b 53 41 50 01 00 02 00 00 00 00 10 00 00 00 00 00 00 00 02
00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00
```

## Compatibility and framing

Only exact version 1.0 is accepted; unknown major or minor versions, flags and
message kinds fail closed. No downgrade, negotiation, resynchronization or
unknown-message skipping. There are no manager-to-agent application responses
in this revision. Future enrollment, acknowledgement and telemetry schemas
require separate reviewed versioning; they must not inherit acceptance from
this codec. No automatic fallback to plaintext or a different endpoint.

`inspect_header` accepts exactly 20 bytes and yields a bounded total length
only after all header checks succeed. `decode` accepts exactly one complete
frame, including its body. It rejects truncation, excess bytes and inconsistent
lengths. The caller must collect fragmented transport reads and separate
coalesced frames before calling it. It must not call the session validator on
partial reads. A future stream reader must read into fixed bounded storage,
inspect the header before reading the body, and close on invalid header,
timeout, EOF mid-frame or cancellation. Do not allocate from advertised sizes.

Future transport requirements: a maximum absolute five-second frame read
budget (including header and body), independent of progress, and cancellation
on shutdown, authorization withdrawal or connection failure. Bound concurrent
connections, rate, queued work and handshake duration before enabling sockets;
those operational budgets are not implemented by this pure codec. A transport
must discard a partial frame and its session on error, with no retry on the
same session. These requirements are design constraints, not measured runtime
properties of M4.1.

## Connection-local order

One noncopyable `SessionValidator` per future authenticated connection, owned
and called serially by the receiver. HELLO must be first with sequence 1.
Only HEARTBEAT is accepted afterward, each with exactly the previous sequence
plus one. Duplicates, reordering, gaps, zero sequence, repeated HELLO and
counter regressions permanently close the validator. Acceptance at UINT64_MAX
closes the validator; no sequence wrap. Explicit closure is irreversible.

A successful `decode` only establishes syntax; `accept` also establishes
connection-local ordering. Neither authenticates, authorizes, stores or acts on
messages. A fresh validator has no knowledge of previous connections. Persistent
anti-replay, certificate-to-agent binding, enrollment/revocation, policy
revalidation, stable event IDs and ingestion idempotence remain requirements.
[M4.3 mutual TLS](TLS_TRANSPORT_M43.md) provides isolated transport-layer
authentication without early data; the codec itself still grants no authority. No cross-session replay defense
or complete TV-07 closure is claimed.

## Errors and diagnostics

The public C++ API returns closed enum categories, with no peer-provided text.
`Truncated`, `Oversize`, `BadMagic`, `UnsupportedVersion`, `UnsupportedKind`,
`ReservedFlags`, `InvalidLength`, `InvalidSequence`, `InvalidPayload` (invalid
encoder fields), `UnexpectedMessage`, `CounterRegression`, and `SessionClosed`
are local errors, not wire messages. Failed header/encode results expose zero
length; failed decode/session results expose an empty default message. The
caller must check `Error::None` before using a result. A future receiver must
close on any rejected frame, record only bounded rate-limited category counts
and approved peer references, never raw frames, counters as identities,
credentials or free-form peer payloads. No audit sink is invoked by this codec.

## Verification

The mandatory `knetsentry_agent_protocol_contract` CTest runs in every preset
including both sanitizer builds. Golden byte vectors, independent decode,
truncation and trailing data, exhaustive single-byte version/flag/type/length
variants, oversized length, invalid encoding, integer bounds, sequence errors,
counter regressions and sticky closure are checked without sockets or privileges.
This is deterministic regression coverage, not exhaustive fuzzing or a TLS
security assessment. See [logical interfaces](../architecture/INTERFACE_CONTRACTS.md)
and [current status](../PROJECT_STATUS.md).

[M4.4 explicit enrollment](ENDPOINT_ENROLLMENT_M44.md) adds an offline ID-to-pin
registry and TLS-backed admission. KSAP payloads remain untrusted reported data;
no wire field may grant or modify enrollment.

## M4.5 extension

See [credential lifecycle](CREDENTIAL_LIFECYCLE_M45.md) for the current
rotation/revocation policy, persistent retired identities and TLS validity
rechecks. The original milestone contracts above describe their historical
scope; operational networking and production administrative integration remain
future work.

## M4.6 extension

See [agent heartbeat and health](AGENT_HEALTH_M46.md) for offline authenticated
reporting, current enrollment revalidation and bounded reconnect scheduling.
Operational network adapters remain future work.

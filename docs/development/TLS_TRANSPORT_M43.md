<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M4.3 — Mutually authenticated TLS transport

The isolated `KnetSentry::Tls` library implements a single-use, single-threaded
TLS 1.3 encrypted byte-stream state machine for I-07/I-08, TB-04, TH-007,
TH-040, TV-06 and KS-NET-008/011/014. It consumes trusted local credentials,
not peer-supplied enrollment data. It creates no sockets, listens on no port,
and does not alter the deny-only production firewall or manager lifecycle.

## Profile and trust

- TLS 1.3 minimum and maximum, X25519 ephemeral key exchange, Ed25519 signature
  algorithms, TLS AES-256-GCM, AES-128-GCM and ChaCha20-Poly1305 suites.
- Both peers must present certificates and prove possession through the TLS
  handshake. OpenSSL path verification uses only the explicit root, strict
  verification, depth zero and security level two. The verification callback
  additionally invokes the [M4.2 identity validator](IDENTITY_M42.md) on the
  bounded encoded leaf, enforcing independent expected peer key pin and role.
- Agent is the TLS client; manager is the TLS server. Local credentials are
  also profile-checked and must match their private key; the expected peer pin
  cannot equal the local key pin. No public CA fallback or hostname-based trust.
- Exact ALPN `ksap/1.0` must be selected before plaintext access. The client
  offers only this token. Missing or incompatible ALPN fails closed.
- Session cache, tickets, resumption and early data are disabled or rejected;
  no renegotiation or post-handshake client authentication is requested.
- The OpenSSL handshake-message callback also requires the local
  CertificateVerify flight; an agent refuses a server that omits client
  authentication. The callback retains no message bytes.
- Trust is local to each endpoint. A client can complete its handshake before
  the server has verified the client's final flight. Do not infer remote
  acceptance from local TLS completion. The receiver must independently reach
  Trusted before any application plaintext can be returned.

## State and wire contract

`include/knetsentry/core/tls_transport.hpp` defines `Session`, `Credentials`,
`State`, `Status` and `Result`. Factory failure returns no session. The factory
retains the OpenSSL credential references and copies the root and peer pin.
The caller must not mutate credential objects during use. A session is not
copyable, is not thread-safe, and cannot be reset or reused after failure.

`ingest` / `drain` transfer ciphertext only through a fixed BIO pair (64 KiB
per direction). Each call accepts at most 16 KiB, may transfer a prefix, and
returns the exact consumed/produced count. The caller must retain unconsumed
bytes in a bounded queue. Handshake input is capped at 256 KiB and handshake
and shutdown have 10-second monotonic deadlines, enforced when the relevant
methods are driven. The caller must schedule progress and independent idle and
connection deadlines; no background thread is created. OpenSSL's own internal
allocations are not claimed to be limited to the BIO capacity. Certificate list
size is capped at 16 KiB and the validated leaf/root encodings at 8 KiB each.

`handshake` progresses until `Trusted`, `WouldBlock` or terminal failure.
Plaintext read/write is forbidden before local trust. A write is limited to
4 KiB; on backpressure retry the identical bytes, not a different message.
The library retains and cleanses the pending buffer. `read` takes a 4 KiB
buffer and returns only successfully authenticated bytes; on failure the
caller buffer is not modified. Reads wait while a write retry is pending. The future adapter must schedule
bounded bidirectional delivery to avoid a simultaneous-write backpressure
deadlock, and abort on its progress deadline.
The transport is a byte stream, not a framing layer; the caller must assemble
complete bounded KSAP frames and run the connection-local protocol validator.
A test transfers a real KSAP HELLO through the encrypted channel.

`shutdown` exchanges close-notify and transitions to Closed only after both
notifications. Drain pending close ciphertext before disposing of the session.
If the underlying transport is lost, call `abort`; it is terminal and does
not turn a truncated TLS stream into a successful close. Failed sessions do
not expose queued ciphertext or plaintext. The API does not expose native SSL
handles, peer input in diagnostic strings or keys in logs.

## DEP-005 extension

M4.3 extends the scoped development-build decision to shared OpenSSL 3.5.x
`libssl` (`OpenSSL::SSL`) alongside `libcrypto`, from the same signed Ubuntu
APT packages `libssl-dev` and `libssl3t64`. No new package or license family,
private runtime, or static OpenSSL linkage is introduced. See the M4.2 review
for provenance and Apache-2.0 obligations. This is APPROVED_FOR_BUILD upon
maintainer acceptance, not APPROVED_FOR_DISTRIBUTION. Exact release artifact
provenance, vulnerability review, transitive license review and SBOM remain
required. No FIPS claim.

## Verification and deployment boundary

`knetsentry_tls_contract` is mandatory in all seven presets. Ephemeral in-memory
certificates and independent raw OpenSSL peer fixtures test mutual identity,
encrypted KSAP, fragmented ciphertext, reverse transfer, backpressure, clean
closure, invalid credential construction, wrong pins, missing certificates,
TLS downgrade, missing/wrong ALPN, a server omitting client authentication,
expired/wrong-role/rogue certificates, corrupted
records, malformed handshakes, bounded input queues and terminal abort. No network, real credentials, root, or external
service is needed. `scripts/verify_m43_tls.py` checks the source integration.

M4.3 proves transport-layer authentication, not enrollment, revocation,
certificate issuance/rotation, application authorization, trusted-time
provisioning, cross-session replay handling or operational network deployment.
Before a real socket adapter is enabled, bind the approved identity and
endpoint to the M3 network policy, revalidate routes and policy, enforce
independent OS restrictions, define revocation/rotation and session invalidation,
and qualify the adapter's I/O, timeouts and cleanup. No threat is closed here.

M4.4 adds the [explicit enrollment registry](ENDPOINT_ENROLLMENT_M44.md)
and a read-only manager-side authenticated agent pin accessor. Enrollment
admission remains separate from TLS trust and operational network permission.

## M4.5 extension

See [credential lifecycle](CREDENTIAL_LIFECYCLE_M45.md) for the current
rotation/revocation policy, persistent retired identities and TLS validity
rechecks. The original milestone contracts above describe their historical
scope; operational networking and production administrative integration remain
future work.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M4.5 — Credential lifecycle

## Policy and authority

The M4.4 offline registry owner remains the administrative authority. The
administrator must independently verify the replacement endpoint and new
Ed25519 public-key fingerprint, obtain a valid role-specific certificate
from the trusted private issuer, and protect the new private key. Renewal
under this profile requires a fresh key; a same-key certificate reissue is
not a way to revoke an older certificate. No CA issuance service or private
key replacement operation is provided here.

With the existing `knetsentry-enrollment` executable, use:

```text
knetsentry-enrollment rotate PRIVATE_DIR ENDPOINT_ID OLD_PIN NEW_PIN
knetsentry-enrollment revoke PRIVATE_DIR ENDPOINT_ID CURRENT_PIN
```

Inputs are canonical lowercase hex (32 ID characters, 64 pin characters).
Both operations compare the expected current pin under the registry lock.
Rotation retires the old key and binds the same endpoint to a new, globally
unused pin in one transaction; there is no overlap/grace period. Revocation
retires the current key and permanently closes the endpoint ID. Neither a
retired pin nor a revoked ID may be approved again. Revocation operates at
the key identity level, covering all certificates for that key, not individual
certificate serials. An old key can still complete standalone TLS with an
incorrectly cached pin; it cannot pass current enrollment admission.

## Storage format and compatibility

The existing `endpoints.v1` pathname and transaction artifacts are retained.
Version 1 (eight-byte header plus 48-byte ID/pin records) remains readable
and is preserved until the first successful rotation or revocation. That
operation atomically publishes version 2 (header version byte 2 plus 49-byte
records: ID, pin, flag 0 active or 1 retired). All pins remain unique;
multiple records for an ID must have all earlier records retired. The last
record determines current status. Unknown versions, invalid flags, duplicate
pins, overlapping active records, malformed lengths and unsafe or uncertain
storage deny. A version-2 store must never be downgraded to version 1;
M4.4 code rejects the new format. The existing lock, ownership, permission,
transaction-marker, exclusive staging, atomic rename and fsync rules apply.

There are at most 128 total records including retired history (6280 bytes in
version 2). Rotation consumes another record; exhaustion denies rotation and
new enrollment but never prevents revoking a currently active key. Do not
prune history, delete the registry, or restore an old snapshot to regain space.
Capacity expansion or authenticated migration must be reviewed separately.
The registry is not tamper-evident or rollback-resistant against root or its
owner; the same trusted path ancestry and filesystem assumptions as M4.4 apply.

## Validity and live session revalidation

OpenSSL chain validation still runs at handshake and local credential creation.
During state observation and transport progress, the TLS state machine checks
current validity of the explicit trust anchor and local leaf, and the verified
peer leaf once trusted. Invalid, not-yet-valid or expired credentials fail
terminally; reads also recheck before copying plaintext to the caller. The
existing monotonic handshake/shutdown deadlines are retained. The validity
checks rely on trustworthy system wall time. They do not establish clock
synchronization, detect all clock rollback, or independently run a timer.

Before handshake, the future manager adapter must obtain the currently approved
pin using `lookup`. `authorize` checks the current registry and actual TLS proof;
`revalidate` performs that check and aborts the session on any denial, including
busy/unsafe/missing storage, stale pins, revoked IDs and expired TLS credentials.
The adapter must invoke `revalidate` before each application operation and on
policy-change notifications, serialize admission with application processing,
and discard pending application bytes/close transport on denial. This is an
explicit API, not an asynchronous revocation broadcast. A previously returned
success is not a durable authorization token. There is no production adapter yet.

For the manager identity, the agent's independently managed current peer pin
must be replaced or removed via trusted local configuration; use
`Session::revalidate_peer` with the current approved pin (or no pin for denial).
A stale pin or absent approval aborts the session. This interface applies to both
roles; it is not a persistent manager trust store, CRL, OCSP client, or automated
trust-distribution mechanism. Future deployment must provide the authoritative
manager trust source and notification/scheduling. No network or monitoring
authority is granted by a positive lifecycle check.

## Recovery procedure

1. For planned renewal, independently verify a fresh key and its certificate,
   stop the old endpoint's use, rotate the approved pin, then start a new TLS
   session using the replacement credential and current approval. Verify denial
   of the old pin. Keep the retired record; securely retire the old key according
   to local key-management procedures. Never overwrite a key in place via M4.2.
2. For suspected compromise, revoke the current pin, terminate affected sessions,
   quarantine the endpoint and investigate. For recovery, independently verify
   a clean endpoint, generate a new key, obtain a valid certificate and explicitly
   enroll a new endpoint ID. Never reuse the revoked ID or any retired key.
3. For expired credentials, do not disable time checks or backdate the clock.
   Verify trusted time and issuer validity, obtain fresh credentials, then follow
   the rotation procedure (or new enrollment if already revoked). For a compromised
   or expired CA, stop use and independently provision a new trust anchor and
   credentials; do not automatically trust peer-supplied roots.
4. On ambiguous I/O, interrupted transaction or corrupt/missing registry, deny
   service, preserve evidence, stop cooperating writers, and reconcile the entire
   snapshot and all retired identities against independently recorded approvals.
   Do not blindly remove transaction files or restore a stale backup. No automatic
   recovery or anti-rollback mechanism is introduced.

Keep actual registry data, pins, key material and certificates out of public
CI and Git. CLI arguments may be visible in shell history/process inspection;
only bounded outcome diagnostics are emitted. Production administrative audit
attribution, issuer operation, protected credential replacement, persistent
manager trust distribution and revocation notifications remain integration work.

## Verification

`knetsentry_credential_lifecycle` is mandatory in all seven presets. The fixture
uses real in-memory TLS, synthetic certificates and private temporary registries;
no network, privileges or real credentials are needed. It covers rotation,
retired pin and revoked ID rejection, stale cached pin denial, persistent
revocation, malformed version-2 flags, manager pin replacement/removal, and
expiration of established sessions and trust anchors. The existing enrollment
and CLI tests also cover capacity and offline lifecycle operations. Run
`python3 -B scripts/verify_m45_lifecycle.py` for the source integration contract.
Traceability: I-07, I-08, TB-04, TH-007, TH-040, TV-06, KS-NET-008,
KS-NET-011, KS-NET-014. Evidence remains partial; no threat closure, release
qualification, operational socket adapter or firewall change is claimed.

## M4.6 extension

See [agent heartbeat and health](AGENT_HEALTH_M46.md) for offline authenticated
reporting, current enrollment revalidation and bounded reconnect scheduling.
Operational network adapters remain future work.

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M5.5 — Secure telemetry buffering and delivery

**M5.7 compatibility update:** The historical commands and state layouts below
precede mandatory `--privacy-policy` configuration. Use the current
[M5.7 contract](PRIVACY_MINIMIZATION_M57.md) for active collector invocations,
redaction and policy-bound journal state. Do not reuse legacy unbound state.

Issue #46, C-08/P-08 and planned I-07, TB-04/TB-06/TB-07. Explicit offline
buffering is usable from the agent. The hardened AgentDelivery library provides
an authenticated single-record exchange and bounded durable receiver inbox;
production socket ownership, network/monitoring authorization, and manager
integration are not deployed. KSAP health traffic remains separate. No new
external dependency, privilege, or remote destination is enabled.

## Opt-in local buffering

Append `--buffer-for ENDPOINT32_MANAGER64` to a valid journal, authentication,
or audit command (not `none`). The value is exactly 96 lowercase hexadecimal
characters: a nonzero 16-byte endpoint ID followed by a nonzero 32-byte approved
manager key fingerprint. These are trusted configuration identifiers, not
credentials or proof of enrollment; they are visible in command arguments.
Use a separate private directory for each endpoint/manager/source profile. The
option starts no network activity. The original collector modes and files are
unchanged; no implicit migration or import. A newly selected outbox starts at
the head of its readable journal, which can overlap prior local-only history.

`telemetry-m55.v1` contains a header `KNETSENTRY-OUTBOX-V1<TAB>binding<TAB>`
followed by the original mode/unit header, a newline-delimited last collected
cursor (empty only before collection), then canonical pending rows. The
checkpoint advances only with a durable append. Acknowledging the oldest row
removes that row but retains the last collected cursor even when the queue is
empty. `telemetry-m55.pending` is the private uncommitted transaction. The
binding and source must match on every restart; changes are rejected, not
redirected or migrated. One active sender per queue, FIFO, 16 records/poll,
128 records and 256 KiB per committed state. No eviction. At capacity, do not
consume another source record; report backpressure. Source-open/read/invalid
record or stale-cursor failure blocks collection while preserving the ability
to deliver previously committed rows. Restart is needed to try collection
again; no silent reset or skip. Storage-integrity or commit failure is terminal.

## Authenticated delivery contract (KSTD 1.0)

A trusted caller must first independently authorize the network operation and
monitoring consent, supply approved identity configuration, negotiate TLS 1.3
mutual authentication using the exact `kstd/1.0` ALPN, and drive ciphertext.
No protocol negotiation or fallback to `ksap/1.0` (the original default) or
plaintext. Existing health tracker/reporter reject telemetry sessions. No
socket, live credential loader or active manager connection is provided here.
Sender checks current manager pin, role, consent/authorization input and queue
binding before each application operation; receiver checks current enrollment,
consent/authorization input, endpoint/manager binding and configured source
before receipt and revalidates enrollment before ACK. A boolean from a trusted
caller is not a network policy decision engine. The caller must independently
apply current policy to every actual ciphertext operation, including final ACK
drain. Session/queue/sink lifetimes must outlive their borrowers. These classes
are single-threaded and require exclusive use of a fresh session.

Eight-byte header: ASCII `KSTD`, version byte 1, kind byte 1 (record) or 2
(ACK), two-byte unsigned big-endian payload length. Record payload is the 96-byte
binding followed by one canonical newline-terminated journal row (maximum 2048
bytes). The ACK payload is exactly 32 bytes: SHA-256 of the complete record
payload. It is a receipt correlation token, not a signature or authorization.
The mTLS session authenticates the response; only an exact matching ACK can
remove the outstanding record. No compression, arbitrary message fields,
control commands or batching. Fixed 4096-byte accumulation and at most one TLS
read/write step per call (receiver may read, commit and write in one call).
Wrong magic/version/kind/length, trailing bytes in the accumulated frame,
wrong digest, invalid row, timeout, policy withdrawal or transport failure
terminate the exchange. Partial progress never extends the five-second
monotonic deadline measured from first application step. A receiver completes
when the ACK is queued to TLS; the caller must drain its ciphertext before
closing. A sender completes only after durable local ACK commit. Use a fresh
TLS session per record; discard connection-local buffers after every outcome.
The existing M4.6 Reconnect scheduler bounds retry attempts (1s initial, 60s
maximum) and is a caller-owned scheduling gate, not transport authority.

## Durable receiver and delivery semantics

`ReceiptInbox` is a reusable local receiver-side sink, not a deployed manager
service. It requires an explicitly selected existing private directory, bound
to endpoint, manager and source; distinct from the sender directory. It checks
canonical rows, matches current configured binding and endpoint, and commits
`telemetry-inbox-m55.v1` through `telemetry-inbox-m55.pending` before accepting a
receipt. The sender's journal cursor is the record key within that profile;
exact duplicates are accepted idempotently, conflicting content is rejected.
128 retained records and 256 KiB; at capacity exact retries still succeed but
new records are rejected without ACK. The inbox does not evict; downstream
consumption/retention is not implemented. A custom ReceiptSink must provide the
same durable and idempotent semantics; it is a trusted, bounded, nonreentrant
callback, never an untrusted extension.

Loss before receipt, after receipt but before ACK, or after ACK before local
commit leaves a retry possible; it never authorizes removal without a valid
receipt. The existing inbox suppresses duplicate inserts across its own restart.
This is at-least-once retry with idempotent acceptance within the retained inbox,
not end-to-end exactly-once delivery or complete journal retention. A source
can rotate while collection is paused; gaps and late inserts remain possible.
A full receiver remains full until a later reviewed consumption mechanism.

## Privacy and storage limits

Both stores reuse owner-only 0700 directory and 0600 regular-file validation,
no symlink path components, hard-link rejection, descriptor-relative writes,
exclusive cooperative lock, file fsync, atomic rename and directory fsync.
Existing metadata minimization applies; no raw message or credentials are added.
These are protected plaintext development stores, not encryption at rest,
cryptographically tamper-resistant evidence, or protection from same-UID/root
writers. Mount identity, crash/power-loss fault injection, production quotas,
retention and secure deletion remain separate work. Do not attach outbox/inbox
files, pending transactions, snapshots, identifiers or actual private telemetry.

## Verification

`knetsentry_telemetry_delivery_contract` uses actual mutually authenticated
in-memory TLS, synthetic journal source, protected disposable outbox and inbox,
and existing registry/certificate fixtures. It covers full queue backpressure,
malformed/wrong ACK, authorization denial, sink rejection, protocol isolation,
concurrent sender/inbox locking, lost ACK, restart on both ends, exact retry,
durable acknowledgment, checkpoint preservation when empty, collection source
loss, revocation, timeout, and bounded inbox capacity/conflict rejection.
The M5.2 native fixture also checks explicitly buffered native selection and
restart. Existing M4–M5 regressions remain mandatory. No actual host journal or
network is accessed by the new mandatory delivery test. Operational transport,
manager ingestion and complete release qualification remain outstanding.

## Maintainer acceptance

2026-11-25 UTC: 107 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED; all 350 configured
CTest executions and nine hosted checks passed. Manual restart retained 63
queued records, unique cursors, destination binding and checkpoint consistency.
Invalid binding and destination substitution were rejected; the focused
authenticated delivery regression passed. Manual GUI verification and merge
were reported. Operational socket and manager receiver integration remain
outstanding under issue #46.

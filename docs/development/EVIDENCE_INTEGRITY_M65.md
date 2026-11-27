<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M6.5 — Original-event preservation and integrity metadata

Issue #55. Development implementation accepted: 126 local gates, 424 CTests, 70 repeated Release regressions, nine hosted checks and no analysis-build diagnostics. M6.6 extends the schema to v4 without replacing existing commitments; see [M6.6](EVENT_SEARCH_M66.md).

## Integrity model

The SQLite development backend retains the exact approved minimized canonical
KSTD row (not uncollected journal messages, audit payloads or file contents).
The immutable evidence commitment includes its assigned ID, configured binding,
configured unit, mode, receiver timestamp and all original canonical bytes,
including native realtime/monotonic timestamps and source provenance. It does
not infer source accuracy or reconstruct redacted fields. Source time and
receiver time retain their separate meanings. Mutable holds and index state are
not covered by the digest; normalized fields still undergo canonical projection
validation. The volatile reference backend exposes no cryptographic commitment.

SHA-256 (OpenSSL Crypto, already approved for development) uses encoding revision
1: ASCII domain `KnetSentry:evidence:sha256:v1` (no NUL), followed by four unsigned
64-bit big-endian integers (origin, event ID, mode, receiver milliseconds), then
three fields (binding, unit, original row), each preceded by its unsigned 64-bit
big-endian byte length. Origin 0 means migration baseline, 1 means admission.
Modes 0/1/2 retain the M6.4 meaning. The result is 64 lowercase hex characters.
A failed digest operation refuses the transaction. A mismatch is IntegrityFailure;
no evidence values are returned on failure. The public RawEvidence result contains
optional EvidenceIntegrity metadata; it is not a signature or authorization token.

## Schema and migration

The existing fixed database filename is retained. Schema v3 adds the strict
`evidence_integrity` table (one digest and origin per event ID), with a foreign
key and transactional cascade on explicit retention. New admission inserts both
original evidence and commitment in the same transaction; retry, indexing and
hold changes never replace the commitment. At M6.5 fresh databases initialized to v3; M6.6 adds search indexes and initializes to v4.
Legacy v1/v2 activation is rejected by default; a trusted caller must explicitly
select `LegacyIntegrityPolicy::EstablishBaseline`. Migration validates the old
schema, canonical evidence and indexed projection, then creates the new table and
baselines old rows in one transaction. A baseline does not attest to pre-migration
integrity. Existing v3 evidence is verified, never repaired or rehashed to accept
changes. Unknown versions and malformed schemas remain rejected. Back up legacy
state offline before explicitly authorizing a migration. No production database
or migration CLI is activated by this increment.

All valid storage operations verify the bounded full evidence set within their
SQLite transaction before returning evidence or changing state, including queries
that would otherwise filter out a changed row. Activation also checks SQLite
integrity. Missing or orphaned commitments and altered schema are rejected.
Corrupt records are not automatically deleted, quarantined or repaired. The
bounded scan (128 records, 2048 canonical bytes each) favors correctness over
throughput; it is not a scalable production verification design. Prior storage
placement, 8 MiB main-file limit, permissions, transaction and ACK separation
remain unchanged. The digest is stored in the same development database.

## Limits and qualification

This is an unkeyed record-integrity model: it detects changes to committed fields
when the corresponding digest remains trustworthy, and missing/orphaned digest
metadata. It cannot authenticate the source, detect coordinated changes to data
and digest, coordinated deletion, whole-database replacement/rollback, alteration
of mutable holds or revision state, or hostile same-UID access. An independent
trust anchor, authenticated manifests, protected key lifecycle, persistent volume
identity, separate raw storage, audit and operational integration remain future
work. Do not publish real records or their hashes: hashes of predictable data can
still reveal information. No new dependency, privilege or network is required.

The mandatory `knetsentry_evidence_integrity_contract` uses synthetic fixtures and
independently calculated SHA-256 vectors, checks exact retry and restart,
explicit legacy migration, malformed legacy refusal, canonical-but-altered
payloads, provenance and digest changes, missing/orphaned commitments, filtered
search refusal, retention cascade and volatile backend distinction. M6.4's
existing rollback, migration and recovery regression remains mandatory.

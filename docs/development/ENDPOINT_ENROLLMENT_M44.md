<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M4.4 — Explicit endpoint enrollment

## Authority and scope

An endpoint approval is a local administrative decision, not a consequence of
passive discovery, a hostname, a network address, a KSAP message or a valid
certificate. An authorized administrator independently verifies the endpoint's
identity and exact M4.2 SHA-256 fingerprint of its raw Ed25519 public key before
recording the approval. The administrator assigns a nonzero opaque 128-bit ID;
IDs are not hostnames, addresses or secret authentication tokens.

The development-only `knetsentry-enrollment` executable is an explicit offline
administrative interface. It is not setuid, not a daemon and not a remote API.
The administrative authority is the effective owner of an explicitly selected
trusted private registry directory. An ordinary user can create their own
unrelated registry; that registry is not thereby trusted by a manager. Future
production integration must establish the canonical directory and authorized
administrator identity through privileged deployment/RBAC and safe path ancestry.
There is no production manager registry selection or operational admission yet.
Do not expose `initialize` or `approve` to any peer, telemetry or discovery path.

## Administrative workflow

The directory must already exist and be owned by the invoking effective UID,
with exact mode 0700. Use a directory outside the source checkout, on a trusted
local filesystem supporting flock, atomic same-directory rename and fsync. The
caller must establish trusted path ancestry; the CLI rejects final symlinks.

```bash
# Synthetic example only: do not use these example identities in deployment.
# Build with cmake --build --preset linux-release first.
store=$(mktemp -d)
chmod 700 "$store"
admin=./build/presets/linux-release/src/core/knetsentry-enrollment
"$admin" init "$store"
"$admin" approve "$store" \
    01010101010101010101010101010101 \
    0202020202020202020202020202020202020202020202020202020202020202
# A duplicate or replacement is rejected. Remove only this synthetic store.
rm -r -- "$store"
```

Real approval requires the independently authenticated fingerprint, not a pin
copied from an untrusted request or this example. The CLI accepts exact lowercase
hex (32 ID characters, 64 fingerprint characters). It provides only bounded
outcomes; values are not echoed. Arguments can appear in shell history/process
inspection; endpoint IDs and fingerprints are not private keys but are sensitive
inventory metadata. Do not put actual approvals or registry files in Git or CI.

## Persistent registry

`KnetSentry::Enrollment` owns a bounded registry in a caller-supplied directory
FD. `init` explicitly creates an empty registry; an absent file is unavailable,
not a valid implicit empty registry. `approve` inserts a unique ID-to-fingerprint
mapping; exact repeats, ID reuse and fingerprint aliasing are conflicts. There is
no overwrite, automatic retry, removal, reset, import or automatic enrollment API.
The limit is 128 approvals. `endpoints.v1` uses an eight-byte header
(`KSENR`, version byte 1, two reserved zero bytes) followed by fixed 48-byte
records (16-byte ID and 32-byte fingerprint). The maximum file is 6152 bytes.
The entire file is checked before lookup or insertion, including duplicate IDs,
duplicate pins, nonzero values, exact lengths and supported version.

The directory and registry must be effective-UID-owned, with modes 0700 and
0600 respectively, and the file must be regular and single-linked. No-follow,
nonblocking and close-on-exec file handling rejects unsafe substitutions.
Cooperating readers and writers use an independent directory file description
and exclusive nonblocking flock; busy storage denies admission. A transaction
creates and syncs `endpoints.v1.pending`, creates exclusive `endpoints.v1.new`,
writes and syncs the bounded snapshot, atomically renames it over the registry,
syncs the directory, removes the marker and syncs again. A marker or staging
file blocks operations until controlled manual recovery. If an I/O error occurs,
no success is reported; a final sync failure can mean the approval was already
durably published. Stop use and verify the complete registry against independently
recorded administrative decisions before recovery. Never blindly delete markers
or recreate a missing registry. This is not an anti-rollback or tamper-evident
store; root, malicious same-UID processes and untrusted ancestor directories are
outside the supported trust boundary. Power-loss behavior has not been fault-injected.

## Authentication and admission

`lookup` returns the approved pin only for a valid known ID. A future manager
adapter must use that pin as `tls::Credentials::peer_pin`, never a peer's own
claimed fingerprint. It must deny unknown, busy, missing, corrupt or unsafe
state. M4.3 TLS validates the private root, agent role, pinned key and proof of
possession. `Session::authenticated_agent()` returns a pin only from a locally
Trusted manager-side session; agent-side, pre-handshake, closing, closed and
failed sessions provide no agent proof. `authorize` re-reads the registry and
compares the TLS-verified pin to the approved ID. A valid certificate alone,
a claimed ID, and passive observations cannot admit an endpoint. Admission does
not mutate the registry or grant monitoring/network permission. A future adapter
must check admission before reading application messages or attaching telemetry
provenance, and must still apply network authorization, enrollment consent,
revocation, trusted time and session-lifetime rules. The existing KSAP wire
format is unchanged; operational endpoint selection and framing remain future
adapter responsibilities.

## Verification and limitations

`knetsentry_enrollment_contract` and `knetsentry_enrollment_admin` are mandatory
in all seven configurations. They exercise persistent approval, duplicate
rejection, invalid IDs/pins, missing and unsafe storage, busy locking, stale
transaction files, duplicate records, unknown versions, oversized files, bounded capacity, actual TLS admission, unknown peers,
wrong endpoint IDs, same-CA wrong keys, agent-side/failed session rejection,
and CLI syntax and no mutation on denied operations. Tests use synthetic keys
and temporary directories, no live network or real credentials. Source contract:
`python3 -B scripts/verify_m44_enrollment.py`.

Traceability: I-07, I-08, TB-01, TB-04, TH-003, TH-007, TH-009, TH-040,
TV-01, TV-06, KS-NET-002, KS-NET-011, KS-NET-032 and KS-NET-038. Evidence is
partial; no threat closure is claimed. Production enrollment RBAC, structured
persistent administrative audit attribution, certificate issuance and rotation,
revocation, registry migration/recovery tooling, rollback protection, remote
socket integration and authenticated telemetry are not implemented here. No
new dependencies, operational service linkage, firewall permissions or GUI
controls are introduced.

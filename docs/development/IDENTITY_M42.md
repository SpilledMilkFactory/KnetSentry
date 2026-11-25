<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M4.2 — Cryptographic identity management

Offline foundation for I-07/I-08, TB-04, TH-007, TH-040, TV-06,
KS-NET-008, KS-NET-011 and KS-NET-014. Key possession, certificate validity,
enrollment, operation authorization and monitoring scope are separate decisions.
This component is not an operational CA, TLS receiver or enrollment service.

## DEP-005 development-build decision

| Field | Decision / evidence |
| --- | --- |
| Owner and review | M4.2 implementation-side review, 2026-11-25; maintainer PR accepted (see [project status](../PROJECT_STATUS.md)) |
| Component | OpenSSL 3.5.x shared libcrypto via `OpenSSL::Crypto`, system-provided `libssl-dev` / `libssl3t64` |
| Origin | Ubuntu 26.04 AMD64 signed APT archive; [Ubuntu source package](https://packages.ubuntu.com/source/resolute/openssl), [upstream](https://github.com/openssl/openssl) |
| Version evidence | Ubuntu archive advertised 3.5.5-1ubuntu3.7 at review; actual target package version must be recorded by CI/local acceptance. Debian 13 implementation environment reports package/header version 3.5.7 (package 3.5.7-1~deb13u2), but the loaded runtime identifies as 3.5.5 and local package verification flags modified library files. Functional results are not package-integrity or security-patch qualification. |
| Integration | The separate identity library and regressions link libcrypto; M4.3 adds the isolated TLS consumer; no vendored sources, private OpenSSL build or automatic runtime download |
| License | [Apache-2.0 upstream](https://github.com/openssl/openssl/blob/openssl-3.5/LICENSE.txt); distro copyright files and transitive dependencies must be reviewed at release |
| Security | Maintained 3.5 LTS branch; distro security updates within 3.5.x permitted for development, not a fixed release lock. Check exact package advisories and artifact graph before deployment. No FIPS claim. Default configured OpenSSL provider environment is trusted local configuration; no custom provider is loaded by this component. |
| Privacy | No network activity, secrets in logs, remote key generation or certificate fetching |
| Integrity / release | Signed APT package provenance; no direct downloads. Exact resolved versions logged; artifact hashes, SBOM, full transitive license review and vulnerability disposition remain release gates. |
| Decision | APPROVED_FOR_BUILD (scoped development use only); not APPROVED_FOR_DISTRIBUTION |

The build requires shared OpenSSL 3.5.x and rejects other minor series and
static linkage. A development test reports the compiled header and loaded
runtime versions; the maintainer must review package provenance and resolve
any unexpected header/runtime discrepancy before accepting the target build. No new permissions or firewall exceptions are introduced.
See the [dependency register](DEPENDENCY_REGISTER.md) and
[approval policy](DEPENDENCY_APPROVAL_POLICY.md).

## Key identity and storage

`KnetSentry::Identity` is Qt-independent and linked by its regression and the isolated [M4.3 TLS library](TLS_TRANSPORT_M43.md). The interface is in `include/knetsentry/core/identity.hpp`.
Agent and manager keys are independently generated via OpenSSL EVP Ed25519.
The public identifier is SHA-256 of the exact 32 raw Ed25519 public-key bytes
(not DER SPKI and not a certificate digest). Role remains a separate field.
This identifier is not secret and is not proof of possession. No application
signing oracle is exposed. The returned owning EVP handle permits subsequent
reviewed CSR and TLS integration.

The trusted caller opens a service-owned private directory and passes an open
directory descriptor; it must verify the intended directory/path ancestry and
retain the descriptor. Only an euid-owned directory with exact mode 0700 is
accepted. Fixed filenames are `agent.key` and `manager.key`. Private keys are
unencrypted PKCS#8 DER, at most 1024 bytes; no passphrases or secrets are
stored in code. The file must be regular, euid-owned, mode 0600, with one link.
No path supplied by a peer is accepted. Reads are relative to the directory
fd, no-follow, close-on-exec and nonblocking; unsafe modes, links, nonregular
files, unsupported keys, malformed DER, trailing data and size violations
fail without a key. OpenSSL validates the private key; application-owned
serialization buffers are cleansed on exit. This is not a guarantee of zero
copies inside the library, encrypted storage, memory locking or protection
against root, same-UID compromise, backups, swap or physical disk access.

Creation is explicit (no automatic replacement). Exclusive staging files in
the same directory use mode 0600, are written and fsynced before no-replace
hardlink publication; staging is then removed and directory fsynced. A
concurrent read during publication can fail closed while two links exist.
A crash may leave a private `.pending` file or a published key even when
creation reports I/O failure. Do not silently delete or regenerate either;
stop the identity consumer and have the owner inspect/recover offline. No
rotation, deletion, export, backup or crash-recovery API is introduced.
The trusted directory and its owner must not be concurrently controlled by an
adversary; no claim of protection against malicious same-UID filesystem races.

## Certificate profile

`validate_certificate` accepts one DER leaf and one explicitly selected DER
root, each 1–8192 bytes. It consumes the entire object and rejects trailing
bytes. The root must be a self-issued, self-signature-valid Ed25519 CA. The
leaf must have a distinct Ed25519 public key, explicit non-CA basic constraints,
digitalSignature-only key usage and exactly one EKU: clientAuth for an agent,
serverAuth for a manager. The independently approved raw-key fingerprint must
match. No common-name or DNS identity fallback is used: operational transport must
bind the expected peer identity from trusted enrollment/configuration, not from
peer input. OpenSSL X509 path verification uses a fresh explicit trust store,
strict verification, self-signature checking, auth level 2, zero intermediate
CA depth, the role-specific TLS purpose and current wall-clock validity.
Only a two-certificate direct chain is allowed. No OS CA store, AIA fetch,
network access, intermediate-chain acceptance or clock override is used.

This is a deliberately restricted initial private-PKI profile, not generic
Web PKI. Issuance policy, trusted time, CSR verification, certificate lifecycle,
revocation, key rotation and certificate-to-enrollment/endpoint authorization
remain mandatory before operational use. [M4.3](TLS_TRANSPORT_M43.md) adds
isolated mTLS proof of possession and early-data rejection; real deployment
and socket adapter qualification remain pending. A success is not authority to connect, enroll or ingest data.
No public provider HTTPS behavior is changed.

## Verification

`knetsentry_identity_contract` uses temporary owner-only directories and
synthetic in-memory certificates, not real keys or system trust stores.
It checks an independent SHA-256 fingerprint golden vector, distinct keys,
reload, no overwrite, private directory/file modes,
symlink and hardlink rejection, FIFO and directory rejection, staging collision,
malformed/oversize/trailing key files, unsupported key algorithms, wrong roles
and pins, explicit invalid-role rejection for create/load/validate (without
storage creation), root-key reuse, wrong/missing
anchor, validity periods, missing/mixed EKU, signature corruption, certificate
truncation and trailing data. Signature corruption is performed with checked
byte access and independently verified to remain parseable but fail signature
verification. Test fixtures are destroyed on normal/handled
failure; a hard kill may leave a private temporary directory. No private key
bytes or certificate contents are printed. No live TLS or revocation coverage
is claimed. See [current status](../PROJECT_STATUS.md).

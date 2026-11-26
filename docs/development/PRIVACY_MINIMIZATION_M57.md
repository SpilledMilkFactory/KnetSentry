<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M5.7 — Privacy and data-minimization controls

Issue #48 extends C-08/P-08 and contributes partial TB-06/TB-07 and
TV-13/TV-25/TV-26 evidence. All active production-agent CLI collector
configurations now require a separate explicit startup privacy-policy
argument. No policy is needed or accepted for lifecycle-only `none`.
This is a local operator policy snapshot, not authenticated management
approval, endpoint enrollment, monitoring consent, OS confinement or
operational network authorization. It does not grant privileges. An
operator controlling the process arguments can replace the policy;
independent policy administration and runtime revocation remain future work.

## Configuration and fail-closed selection

The existing schema-version-1 collector arguments remain, with a mandatory
final `--privacy-policy POLICY` pair for every active collector. The policy
is a single quoted ASCII argument with grammar `v1;key=value;key=value...`.
It is bounded to 24,576 bytes and 48 directives. No whitespace normalization,
comments, escaping, wildcard expansion, empty entries, unknown keys,
unknown values or duplicate directives are accepted. The policy must name
exactly one matching collector. Irrelevant permissions and redactions are
rejected, rather than silently ignored.

| Directive | Meaning |
| --- | --- |
| `collector=journal`, `authentication`, `audit` or `fim` | Exactly one, must match the selected collector |
| `allow-unit=NAME.service` | Exact service selection; required for journal/authentication; repeat for other approved services |
| `deny-unit=NAME.service` | Exact exclusion; takes precedence over allow |
| `allow-path=/absolute/file` | Exact approved FIM file; one to eight unique allow entries |
| `deny-path=/absolute/path` | Exclude exact path and descendants at component boundaries |
| `permit=journal-identifiers` | Required for journal/authentication/audit; native cursor, times, machine/boot IDs and source are retained |
| `permit=auth-message` | Required to inspect and classify authentication messages unless auth-category is redacted |
| `permit=audit-identifiers` | Required for audit; numeric record type and audit ID are retained |
| `permit=file-content` | Required for full FIM hashing unless content is redacted |
| `permit=buffering` | Required if and only if `--buffer-for` is supplied |
| `redact=auth-category` | Authentication only; do not request MESSAGE, retain fixed `redacted` rather than classification |
| `redact=fim-content` | FIM only; no data open or SHA-256 file hashing, metadata-only observations |
| `redact=fim-slot` | FIM only; omit the configured slot from change diagnostics |

The same literal unit and path syntax restrictions as the original collectors
apply. Authentication allow entries must be supported authentication units.
An excluded or unlisted requested source rejects the entire configuration
before collector construction, rather than silently starting partial monitoring.
Audit has fixed source `_TRANSPORT=audit` and cannot accept unit/path entries.
Local machine ID is now included in the native match for all production journal
modes. Invalid configuration exits 2 with a fixed diagnostic; privilege policy
is still checked first for structurally valid active invocations. Policy parsing
and fingerprint computation follow privilege normalization and restrictive umask.
Policy is not a file path and the agent does not read a separate policy file.
Arguments are visible to permitted local process inspection: keep the policy
and real source paths out of public logs and artifacts.

## Examples (ordinary non-root development account)

Metadata-only authentication (no inspection of message text):

```sh
umask 077
state=$(mktemp -d "$HOME/ks-privacy-m57.XXXXXX")
policy='v1;collector=authentication;allow-unit=systemd-logind.service;permit=journal-identifiers;redact=auth-category'
knetsentry-agent --run --schema-version 1 --collectors authentication --unit systemd-logind.service --state-dir "$state" --privacy-policy "$policy"
```

For classified authentication replace `redact=auth-category` with
`permit=auth-message` and choose a **new private state directory**. For journal
metadata use `v1;collector=journal;allow-unit=NAME.service;permit=journal-identifiers`
with an actual permitted service. For audit use
`v1;collector=audit;permit=journal-identifiers;permit=audit-identifiers`.
For buffering append `;permit=buffering` to the policy and supply
`--buffer-for` before the final privacy argument, with a new private directory.
No networking is enabled.

Content-free file monitoring:

```sh
umask 077
fixture=$(mktemp -d /tmp/ks-privacy-fim.XXXXXX)
printf 'synthetic\n' > "$fixture/watched"
policy="v1;collector=fim;allow-path=$fixture/watched;redact=fim-content;redact=fim-slot"
knetsentry-agent --run --schema-version 1 --collectors fim --path "$fixture/watched" --privacy-policy "$policy"
```

Readiness is `fim=metadata-only`; changing permissions produces
`knetsentry-agent: fim change; kind=metadata-changed`. The existing restricted
O_PATH resolution, parent pin, regular single-link object and size/identity
checks remain. The content-free branch returns before opening the inode for
content or allocating a digest context. It cannot detect a content-only change
as such. Metadata changes, deletion, creation and replacement remain visible
when sampled. In full FIM replace `redact=fim-content` with `permit=file-content`;
optionally remove `redact=fim-slot` to retain the numbered slot. No persistent
FIM state is introduced. Denying the parent (append `;deny-path=$fixture`)
rejects the entire startup even if the leaf is explicitly allowed.

## Persistent state and policy changes

Every CLI-created journal state/outbox uses its existing file name with a new
first line `KNETSENTRY-PRIVACY-V1<TAB>SHA256(policy bytes)`, followed by the
previous source/destination header, checkpoint (outbox only) and rows. Exact
policy bytes, including directive order, must match on reopening. The hash is
a configuration consistency marker, not a signature or secret. State remains
protected plaintext with the existing owner-only permissions, lock and atomic
replacement. Authentication rows must match the configured redaction mode on
load and on commit. Existing unbound state or a different policy fingerprint
is rejected before journal opening; it is not migrated, overwritten, deleted
or delivered. A mismatch exits 1. Preserve existing evidence separately under
its original protections; use a new private directory for a deliberately
reviewed policy change. Re-collection from the head in a new directory may
produce overlapping evidence; no automatic deduplication across stores,
retention or secure erasure is provided. Never edit the fingerprint to force
acceptance. A new policy does not retroactively redact previously stored records.

For isolated native fixtures the underlying library retains its original
unbound constructor default. This is not a CLI bypass; independently authorized
production callers and receiver-side policy binding remain future integration.
The `redacted` category extends the authentication row vocabulary (old
receivers may reject it; no fallback). KSTD framing is unchanged; there is
no operational socket integration, negotiation or receiver-side policy check.
The opaque native cursor may contain machine/boot/time-related values; the
collector cannot safely remove these mandatory recovery fields. Reject the
collection if `journal-identifiers` or required audit metadata is not approved.
No hashing or substitution of these fields is represented as anonymization.
Raw messages, account/IP values, key fingerprints, arbitrary audit arguments,
file contents and other unapproved fields remain excluded from persistence or
output according to the previous collector contracts. Full FIM and classified
authentication still acquire bounded content transiently when expressly permitted.
No new privileges, permissions, external dependency, remote action or network
connection is introduced. Existing OpenSSL Crypto scope extends to policy hashing.

## Verification and limitations

`knetsentry_privacy_policy_contract` is mandatory in all seven presets. It
launches the real unprivileged agent against synthetic files, exercises absent,
malformed, duplicate, unknown, denied and conflicting policies, tests exact
path and unit exclusions and sensitive permits, confirms no denied-file opens
or reads with an inotify positive control, verifies slot and metadata-only FIM
redaction without content acquisition, and rejects legacy/differently bound
state without mutation before source access. The existing native authentication
fixture regression also verifies actual redacted journal rows, restart, policy
change rejection, legacy reader rejection and malformed redacted-state rejection.
Existing FIM/agent runtime tests supply explicit policies and retain all prior
filesystem and privilege checks. No actual host log or private file is needed
for the new regression. The structural verifier is not runtime qualification.

The policy is static until restart, one collector per process. No centrally
signed policy, independent runtime policy distribution, hot reload, production
retention, retroactive redaction, full end-to-end receiver enforcement,
production agent confinement or comprehensive security audit is claimed.
M4.7 #40 and M5.5 #46 operational integration remain outstanding. Do not upload
actual policy strings, state files, credential material or private file contents.

## Maintainer acceptance

On 2026-11-26 UTC the maintainer recorded 111 PASS, 0 FAIL, 0 SKIPPED,
0 BLOCKED, 364 passing CTest executions and nine successful hosted checks
(`420215f`). Manual verification confirmed full and metadata-only FIM,
policy rejection, 63 retained redacted records after restart, and changed-policy
rejection without state mutation. GUI verification and merge were reported.

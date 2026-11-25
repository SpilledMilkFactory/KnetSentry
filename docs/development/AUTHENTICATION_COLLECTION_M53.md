<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M5.3 — authentication and SSH event collection

Issue #44 extends C-08/P-08 with explicitly selected local authentication
observations, using the M5.2 native journal and checkpoint transaction. No
new privileges, network connections, enrollment, monitoring consent, external
sources, command execution, raw-event repository or production spool are added.

## Configuration

```bash
umask 0077
state=$(mktemp -d "$HOME/ks-auth-m53.XXXXXX")
./build/presets/linux-release/apps/agent/knetsentry-agent \
    --run --schema-version 1 --collectors authentication \
    --unit ssh.service --state-dir "$state"
```

Select only one locally authorized unit per process. Supported literal source
profiles: `ssh.service`, `sshd.service`, `ssh@INSTANCE.service`,
`sshd@INSTANCE.service`, `login.service`, `getty@INSTANCE.service`,
`serial-getty@INSTANCE.service`, and `systemd-logind.service`. Wildcards and
unrecognized units are rejected. No permission changes, root execution, SSH
server installation, or journal-group membership are required. No readable
records means unknown coverage, not absence of authentication activity. The
original `none` and `journal` modes retain their existing semantics.

## Classification and privacy

Only authentication mode reads a bounded `MESSAGE` view (maximum 1024 printable
ASCII bytes); raw content is not copied into the record or logged. OpenSSH
accepted/failed methods, invalid-user reports, PAM unix authentication failures
and session open/close, traditional login failures, and logind new/removed
sessions map to a closed enumeration. SSH IPv4 and IPv6 endpoints and numeric
ports are checked syntactically, not contacted. Common public-key and PAM
suffixes are supported. Unknown, missing, oversized, binary, localized, or
unsupported message forms are retained as `unclassified` metadata checkpoints,
not asserted to be authentication failures or successes. Other journal read
errors terminate collection. Classification is source-reported advisory evidence,
not proof of actual authentication, session ownership, or endpoint identity.
The selected trusted journal unit provides provenance, not proof that a message
is genuine. Duplicate MESSAGE fields are not independently authenticated or
resolved; native field selection and source trust limitations apply.

No username, address, port, session identifier, password, command, fingerprint,
message body, or arbitrary field is persisted. The remaining timestamps,
identifiers, cursor, unit and category are still sensitive. This intentionally
limits later correlation until separately reviewed privacy and normalization
contracts are implemented. No `/var/log/auth.log`, auditd, display-manager,
localized messages, arbitrary PAM modules or cross-unit correlation are covered.

## Durable state

Use a new private state directory (mode 0700) outside the checkout. The file
`auth-m53.v1` has mode 0600, header `KNETSENTRY-AUTH-V1<TAB>unit` and the
six M5.2 fields followed by one fixed event-category token. `auth-m53.pending`
is the exclusive transaction file. The original `journal-m52.v1` format and
checkpoint remain separate. No migration or reinterpretation is performed.
Each selected record including unclassified records is committed with its
cursor. Exact seek/test recovery, duplicate rejection, ownership, permissions,
locking, atomic file/directory synchronization, 16-record batches, 128-record
limit and 256 KiB cap remain inherited from M5.2. A stale cursor or corrupt
category fails closed; no automatic reset or eviction. Scope/category mismatch
is rejected on load. Unknown records consume capacity; choose a bounded source
for development. Late journal insertion, rotation gaps, power-loss testing,
same-UID tamper resistance and production retention remain outstanding.

Never attach the state, pending files or `before-restart.snapshot`. The manual
state is under the home directory, not necessarily under build/. Export tracked
source with `git archive` and share reviewed acceptance reports separately.

## Verification

`knetsentry_authentication_collection_contract` is mandatory across all seven
presets. It exercises representative SSH aliases, instance units, IPv4/IPv6,
PAM variants, login/logind, malformed messages, unsupported source, missing and
oversized messages, category validation, real native extraction and selection,
privacy canaries, exact restart and stale checkpoint rejection. The embedded
SHA-256-checked fixture contains 13 fabricated native records, including an
excluded service. It was generated with a disposable systemd 257 writer, not
with operational host logs. No private writer ABI or systemd binary ships.
Existing M5.2 and M5.1 regressions remain mandatory; the M5.1 runtime verifier
also checks rejected authentication configuration and missing private directory.
The normal journal mode remains metadata-only. No new dependencies.

Target-host live verification is conditional on already readable authorized
records; never deliberately fail real logins or grant additional permissions
for a test. Report only aggregate categories and counts, not raw state.

## Maintainer acceptance

On 2026-11-25 UTC the maintainer reported 103 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED,
336 configured CTests, nine hosted checks and merge. Live collection retained 63
records, including 14 session-removal observations and 49 unclassified records;
restart preserved 63 unique cursors. Manual schema, permissions and negative CLI
checks passed. M5.4 adds a separate audit mode; existing formats are unchanged.

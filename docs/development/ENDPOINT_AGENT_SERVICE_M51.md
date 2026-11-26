<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M5.1 — Endpoint-agent service architecture

At the M5.1 baseline, issue #42 introduces `knetsentry-agent`, a foreground Linux process independent
of the manager and desktop. It links only the Qt-independent
`KnetSentry::AgentLifecycle` library. It does not enroll, connect, collect,
read protected host records, emit telemetry, or persist a spool.

## Startup and configuration

```bash
./build/presets/linux-release/apps/agent/knetsentry-agent --run --schema-version 1 --collectors none
```

The entire version-1 configuration is explicit, ordered command-line arguments.
No environment-based configuration, file discovery, fallback, secret arguments,
unknown keys, extra arguments or collector selection other than `none` is accepted.
`--help` is informational. Invalid configuration returns 2; rejected privilege
policy returns 3; lifecycle, signal or output failures return 1. Successful
SIGINT/SIGTERM shutdown returns 0. Readiness means only lifecycle readiness;
monitoring remains unavailable. This is not an enrollment or monitoring grant.

## Collector interface

A trusted statically linked `Collector` implements `start()` and `stop()`;
stop must tolerate partially completed startup. Borrowed collectors outlive
`Lifecycle`. Registration is validated before any startup side effect: at most
eight distinct non-null modules. Start is ordered; cleanup is reverse-ordered,
including the failed module. Terminal states cannot restart; stop is idempotent.
No plugin loading, worker scheduling, event format or real collector is supplied.
Modules must be synchronous, bounded and non-reentrant; future collector
implementations must define cancellation and resource limits before activation.

## Privilege separation

C-08/P-08 runs unprivileged. Startup rejects zero or mismatched real/effective/
saved UID/GID, and nonempty effective or permitted capabilities. An ordinary
login can carry inheritable-only capability bits. The agent sets and verifies
Linux no-new-privileges, removes any inheritable-only bits with a zero-only
capability update, and reads back all capability words to require empty
effective, permitted and inheritable sets before readiness. Ambient bits are
a subset of permitted and inheritable bits and therefore must also be empty.
A failed query, restriction, removal or readback rejects startup with exit 3
and a fixed reason, never a caller-controlled value. The agent sets umask 0077. SIGINT/SIGTERM
are blocked before readiness and consumed synchronously. There is no root
operation, helper invocation, IPC endpoint, socket creation or file creation.
This is an application startup policy, not a sandbox: inherited descriptors,
supplementary groups and ordinary account permissions are deployment concerns.
Development execution uses an ordinary user with clean standard streams.

Future production deployment must use a dedicated non-login identity, reviewed
supplementary groups, empty capability bounding/ambient sets, closed inherited
nonstandard descriptors, protected credentials/state, service resource limits,
filesystem restrictions and independent default-deny network enforcement. No
unit or account is installed by M5.1. C-09/P-09, if required, must be a distinct
restricted helper with separately approved source reads and authenticated I-09
IPC, never a root agent or generic command executor. I-07 remains disabled
until enrollment, scope and independent transport enforcement are integrated.

## Qualification

```bash
ctest --preset linux-release -R '^knetsentry_agent_(lifecycle_contract|service_runtime)$' --verbose --no-tests=error
```

The mandatory compiled lifecycle regression verifies bounds, invalid registration,
rollback, terminal states and cleanup. The subprocess regression rejects invalid
configuration, inspects actual Linux process identity, capabilities, no-new-privileges,
umask and open descriptors, exercises SIGTERM and SIGINT and checks no working
directory writes. It requires an ordinary non-root user; root-only negative
qualification may be performed separately. Tests use no live endpoint evidence.
Readiness is checked with bounded reads and reports early child exit status
and recognized fixed startup diagnostics; the caller capability masks are
reported for environment diagnosis. The original target-host run failed only
the runtime CTest in all seven presets and the explicit verbose repetition
(87 PASS, 8 FAIL, 3 SKIPPED, 0 BLOCKED); privileged gates were withheld.
An inheritable-only launch reproduced the original rejection in a controlled
fixture. The original log did not identify the exact privilege failure on the
target host. The corrected process must still expose zero CapEff, CapPrm,
CapInh and CapAmb, without changing the caller capability sets.
The two tests are mandatory in all seven presets. No production service sandbox,
helper privileges, operational networking or telemetry qualification is claimed.
Target-host and hosted M5.1 acceptance completed on 2026-11-25; see
[project status](../PROJECT_STATUS.md). M5.2 adds an explicit journal-only mode
and native library linkage; see the [M5.2 contract](JOURNAL_COLLECTION_M52.md).

M5.6 adds explicitly selected file integrity polling and existing system
OpenSSL Crypto linkage for SHA-256. See the [M5.6 contract](FILE_INTEGRITY_M56.md).

M5.7 requires an explicit final privacy-policy argument for all active CLI
collector configurations, without changing `none` or granting privileges.
See [M5.7](PRIVACY_MINIMIZATION_M57.md).

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M2.8 — Service lifecycle and IPC integration

Issue #25 extends the existing M2.1–M2.7 regression suite; it does not change
production authorization, the service protocol, GUI behavior or systemd policy.
The mandatory `knetsentry_service_lifecycle_ipc_integration` CTest executes the
actual compiled manager and native health-client probe in every preset. It uses
synthetic local AF_UNIX traffic and private disposable directories under `/tmp`.
It never installs or starts the installed system service.

## Scenario and evidence matrix

| Scenario | Required observation | Coverage |
| --- | --- | --- |
| Startup without IPC, invalid configuration, unsafe directory | Lifecycle and fail-closed exit contracts | M2.1–M2.3 existing tests |
| No daemon, running manager, stopped manager | Native client unavailable/available/unavailable | M2.8 and M2.6 |
| Duplicate startup | Exit 5, no readiness, unchanged socket inode, original service responds | M2.8 |
| Fragmented valid request | Exact legacy STATUS response | M2.8 |
| Zero, 65 and maximum uint32 frame lengths; invalid version, ID, terminator and payload; 64-byte invalid message | No response, rejection counter and audit records | M2.8 |
| Explicit administrative request | No response, distinct denial event | M2.8 |
| Incomplete header/body with write-side shutdown | No response, transport counter and recovery | M2.8 |
| Incomplete header/body with open write side | Server closes within bounded client timeout, no response, recovery | M2.8 |
| Different UID and matching UID with different GID | Connected peer receives no data, authentication counter and kernel-derived actor | M2.8, conditional root harness |
| SIGINT and SIGTERM | Successful exit, ordered lifecycle diagnostics, owned socket cleanup | M2.8 |
| Graceful restart on same path | Fresh process-local counters and available native client | M2.8 |
| SIGKILL and stale socket | Client unavailable, no fabricated shutdown audit, restart rejected without replacing inode | M2.8 |
| Explicit fixture recovery | Remove only the reaped test process's stale entry; fresh service succeeds | M2.8 |
| Audit continuity | Distinct session IDs, ordered records, exact previous evidence preserved, private metadata and redaction | M2.8 and M2.5 |
| Audit sink failure | Response withheld, exit 6, socket cleanup | Existing M2.5 runtime |
| Invalid/stalled server responses and wrong server identity | Native client rejects/unavailable | Existing M2.6 tests |
| Actual QML disconnect/reconnect | Model and dashboard follow real manager transitions | Existing M2.6 desktop test |
| Installed service confinement | Dedicated identity, actual kernel controls, authorized health and outsider denial, audit | Separate M2.7 administrator gate |

## Invocation and evidence boundaries

```sh
ctest --preset linux-release -R '^knetsentry_service_lifecycle_ipc_integration$' --verbose --no-tests=error
python3 scripts/verify_m28_lifecycle_ipc.py --build-dir build/presets/linux-release
```

CTest has a 90-second outer timeout; subprocess and socket operations have
individual deadlines. A refused connection or a read timeout cannot satisfy an
IPC denial assertion: the peer must connect and observe EOF or a connection
reset/broken pipe without any returned data. The ordinary unprivileged runner
reports distinct-identity subcases as NOT_APPLICABLE; it still runs all other
scenarios. A root test harness, where supported, starts the daemon as UID/GID
65534 and uses root and same-UID/different-GID clients to exercise actual peer
checks. Do not run ordinary repository acceptance as root. The root harness
is intended for disposable development environments with that capability.

Every audit fixture is isolated. Earlier session files are compared byte for
byte after restart; raw records, session identifiers and peer identities are
not printed. The test does not claim tamper-proof evidence or automatic crash
recovery. A foreground SIGKILL can leave a stale socket; removal in the test is
limited to its private fixture after reaping the process and verifying that
failed startup did not replace the entry. Never automatically remove an
operator's existing socket or audit files.

This advances the initial read-only subset of TB-05/I-01, KS-NET-012,
TH-010 and TV-08. Audit redaction and continuity also exercise TB-07,
TH-033 and TV-25. The current same-UID/GID model does not distinguish processes
sharing that identity, and these tests do not qualify future administrative
roles or establish complete threat closure. No LAN monitoring, remote access,
privileged response or cross-identity desktop authorization is introduced.
Source verification checks registration and evidence boundaries; it is not
runtime evidence. Full Ubuntu desktop/CI and separate installed systemd
qualification retain their existing acceptance requirements.

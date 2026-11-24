<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M2.1 — Management daemon lifecycle foundation

**Issue:** #18 · **Component:** `C-01` · **Process:** `P-01` · **Target:** Ubuntu 26.04 AMD64.

## Implemented scope

`knetsentryd` is a standalone C++23 **foreground-only** process linked to
`KnetSentry::Core` and `KnetSentry::Service`. It does not link Qt, start a GUI,
open network sockets, access databases, capture packets, or perform privileged
operations. Building `linux-core-only` also builds and tests the daemon.

The daemon rejects running with effective UID 0 (exit code 3), does not attempt
privilege dropping or daemonization, and is designed to be started by a normal
non-root operator or a future dedicated systemd service user. An actual systemd
unit, sandbox policy, readiness notification, service registration and runtime
permissions will require a separate reviewed issue. **Do not install or run
this proof-of-lifecycle binary as root.** No `sudo` is needed to run it.

### Defined lifecycle transitions

| Initial state | Operation | Result | Otherwise |
| --- | --- | --- | --- |
| `Created` | `begin_start()` | `Starting` | reject |
| `Starting` | `mark_ready()` | `Running` | reject |
| `Starting` or `Running` | `request_stop()` | `Stopping` | reject |
| `Stopping` | `complete_stop()` | `Stopped` | reject |
| Any nonterminal state | `mark_failed()` | `Failed` | reject |

`Stopped` and `Failed` are terminal; no implicit retries or restarts. The state
machine is single-thread-owned, not a thread-safe scheduler. An interrupted
startup may proceed through `Starting -> Stopping -> Stopped`. All illegal and
duplicate transitions are rejected and covered by compiled tests.

### Signals and lifetime

The main process blocks `SIGTERM` and `SIGINT` before declaring readiness, then
waits with POSIX `sigwait()`. There is **no asynchronous C++ signal handler**.
After receiving either signal it enters `Stopping`, reports an ordered event,
enters `Stopped`, and exits zero. Failure to establish the signal mask, advance
a required state, or publish a critical lifecycle record results in a nonzero
exit. `SIGKILL`, host power failure, or a broken output sink cannot guarantee a
final record. No automatic restart, watchdog, or health guarantee is claimed.

`Ready` means **only** that the process is running and can accept stop signals.
It does **not** mean any sensor, manager API, event store, network listener,
audit service, or detection engine is active. The desktop remains independent
and continues to report monitoring unavailable.

### CLI and diagnostics

```bash
cmake --preset linux-release --fresh
cmake --build --preset linux-release --parallel
./build/presets/linux-release/apps/manager/knetsentryd --help
./build/presets/linux-release/apps/manager/knetsentryd --version
./build/presets/linux-release/apps/manager/knetsentryd
# In another terminal: kill -TERM <PID>, or Ctrl+C in the foreground terminal.
```

Unsupported options are rejected with exit code 2. Runtime writes only four
allowlisted M1.6 JSONL diagnostic events to stderr: `manager_starting`,
`manager_ready`, `manager_stopping`, `manager_stopped`. They contain no arbitrary
strings, credentials, file paths, endpoint identifiers, or private context.
The logger is **non-authoritative**: its sequence numbers are process-local and
its output is not durable or authenticated audit evidence. CLI --help and
--version return without starting a daemon or emitting lifecycle records.

### Trust boundaries, exclusions, and future work

- `TB-05` (local GUI/CLI to management IPC) **is not implemented**. The manager
  has no request parser, client authorization, IPC listener, or admin API.
- No raw-event directory creation, SQLite, authentication, network interfaces,
  public CVE/feed access, device monitoring, privileged helper, or AI worker.
- The M0.2 LAN/egress contracts and M0.3 threats remain unchanged; process
  lifecycle tests cannot verify future network isolation or authorization.
- Actual systemd unit/sandbox, privilege retention, clean restart/recovery,
  IPC authentication, daemon health, logging durability, and failure injection
  are future M2/M3/M13 gates with separate acceptance evidence.

## Verification

```bash
python3 scripts/verify_m21_manager.py
cmake --preset linux-release --fresh
cmake --build --preset linux-release --parallel
ctest --preset linux-release --output-on-failure
python3 scripts/verify_m21_manager.py --build-dir build/presets/linux-release
cmake --preset linux-sanitize --fresh
cmake --build --preset linux-sanitize --parallel
ctest --preset linux-sanitize --output-on-failure
reuse lint
```

The two new CTests `knetsentry_manager_state_contract` and
`knetsentry_manager_signal_lifecycle` must pass in **all** configurations,
including both core-only and full sanitizers. The external-process test
executes the **real** daemon, checks ordered bounded JSONL records and both
SIGTERM/SIGINT paths, rejects unknown CLI options, and tests root denial when
run as root in an isolated test environment. Test fixtures use no network
connections or sensitive production data. Source-only verification does not
qualify executable behavior.

**Expected totals after M2.1:** desktop Release/Debug/Clazy/analysis **15**;
full sanitizer **12**; core-only **7**; core-only sanitizer **8**. These are
planned inventories until executed on the exact revision and in GitHub Actions.

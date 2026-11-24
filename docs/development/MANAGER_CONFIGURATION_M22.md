<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M2.2 — Versioned manager configuration contract

**Issue:** #19 · **Target:** Ubuntu 26.04 AMD64 · **Scope:** C++23 Qt-independent manager.

## Versioned, deliberately restrictive schema

M2.2 adds a minimal, **versioned**, strongly typed configuration parser for
`knetsentryd`. Schema v1 is *lifecycle only*. It does **not** grant operational
SIEM capabilities, network access, service privileges or security-event storage.
The required seven keys (exact spelling, exactly once) are:

```text
schema_version = 1
mode = lifecycle_only
monitoring_enabled = false
network_listeners_enabled = false
packet_capture_enabled = false
public_intelligence_enabled = false
privileged_actions_enabled = false
```

All seven fields are mandatory when a file is supplied. The configuration
values are typed in `ManagerConfiguration` (numeric version, enumerated mode,
boolean security policy switches). The parser accepts ASCII spaces around `=`
and whole-line `#` comments; it does **not** interpret quotes, escapes, inline
comments, environment substitution, includes, URLs, or arbitrary key/value
pairs. A future key, version, mode, duplicate key, missing key, invalid value,
BOM, tab, CRLF, NUL, or unrecognized byte fails closed. No configuration
migration or permissive parsing is performed; expanding permissions requires
a separately reviewed future schema version and corresponding authorization
tests. Input is limited to 4096 bytes and 32 lines.

### Loading, provenance and permissions

- `knetsentryd` with **no `--config`** retains M2.1's built-in safe defaults:
  all security capabilities disabled and lifecycle only.
- `knetsentryd --config ABS_PATH` explicitly requires an approved schema v1
  file. If missing, invalid, unsafe or unreadable, the daemon exits **4**
  and must **not** emit `manager_ready`. There is **no fallback** to defaults
  when the operator explicitly provides a configuration path.
- `knetsentryd --check-config ABS_PATH` validates the file without starting
  the daemon; success is 0 and rejection is 4. Neither command echoes file
  contents, path, secret material or untrusted error strings.
- The path must be absolute, ASCII and free of `.` / `..` components. The
  opened final component must be a regular file **owned by the effective
  service UID**, with exactly one link, no executable bits and **mode 0600 or
  more restrictive**. Symlinks in the final component, directories, FIFOs,
  devices, group/world-readable or writable files are rejected. The file
  is opened with `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`; metadata is rechecked
  after a bounded read to detect ordinary concurrent modification.
- **Limitation:** parent-directory symlinks are not yet rejected and concurrent
  same-UID writes cannot be made atomic by this lightweight reader. Put the
  config in an operator-controlled directory and update via atomic replacement.
  Future systemd service installation must review directory ownership and
  protect parent components as well as the final file. This is a local
  trust-boundary improvement, not a blanket filesystem-race guarantee.

### Ubuntu 26.04 development example

```bash
cd ~/Documents/CPP_Projects/KnetSentry
install -m 600 examples/manager-v1.conf "$HOME/knetsentry-manager.conf"
./build/presets/linux-release/apps/manager/knetsentryd \
  --check-config "$HOME/knetsentry-manager.conf"
./build/presets/linux-release/apps/manager/knetsentryd \
  --config "$HOME/knetsentry-manager.conf"
# Press Ctrl+C to stop the foreground process.
```

The example in the Git checkout is deliberately not suitable for direct use:
its checked-in file permissions are not authoritative. Use `install -m 600`.
Never run the management process as root.

### Diagnostics and failure semantics

An explicit invalid configuration causes a fixed `manager_failed` JSONL event
with rejected outcome and a generic `configuration rejected (no fallback)`
message. There is no ready event, no network bind, no file creation, and no
privileged action. Valid configuration leaves the four M2.1 startup/stop
records unchanged. The M1.6 logger is **non-authoritative**: these records
are not a protected security audit trail.

### Security and architectural boundaries

- `TB-05` local GUI-to-manager IPC is unimplemented; M2.2 does not introduce a
  manager socket, request authorization, or network listener.
- The M0.2 LAN policy and permitted public intelligence access remain *design
  requirements*, not operational network functionality. The v1 setting for
  public intelligence is necessarily false, even though future explicitly
  approved public HTTPS lookups are planned.
- No raw-event storage path or independent database location is selected at
  M2.2. The pre-existing future requirement for user-selectable raw-event and
  database storage, with mount safety, remains unchanged and unimplemented.
- No secrets, certificate material, agent credentials, or external endpoints
  are accepted in this schema. The manager still has no operational SIEM.

## Verification

```bash
python3 scripts/verify_m22_configuration.py
cmake --preset linux-release --fresh
cmake --build --preset linux-release --parallel
ctest --preset linux-release --output-on-failure
python3 scripts/verify_m22_configuration.py --build-dir build/presets/linux-release
cmake --preset linux-sanitize --fresh
cmake --build --preset linux-sanitize --parallel
ctest --preset linux-sanitize --output-on-failure
reuse lint
```

`knetsentry_manager_configuration_contract` runs compiled parser negative
cases; `knetsentry_manager_configuration_runtime` tests real daemon startup
and file security policy, including version rejection, duplicate/unknown keys,
unsafe feature toggles, group/world permissions, symlink/FIFO/directory
rejection, oversized input, and no-fallback behavior. **Expected M2.2 CTest
inventory:** desktop Release/Debug/Clazy/analysis **17**, full sanitizer
**14**, core-only **9**, core-only sanitizer **10**. Source-only checks do not
prove runtime behavior; the full Ubuntu 26.04 and GitHub-hosted matrix remains
subject to acceptance on the exact revision.

**M2.3 compatibility:** Optional `--ipc-dir` enables a local Unix-domain
listener only; schema-v1 `network_listeners_enabled = false` remains required.
The explicit configuration is validated before IPC socket creation, and no
rejected configuration is replaced by a fallback. See
[local authenticated IPC](LOCAL_AUTHENTICATED_IPC_M23.md).

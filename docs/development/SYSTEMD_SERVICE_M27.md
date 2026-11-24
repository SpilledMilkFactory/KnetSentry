<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M2.7 — Initial systemd service integration and hardening

Issue #24 adds an administrator-installed **development** system service for
P-01/C-01. It is not a release package, installer, or operational SIEM. The
normal CMake build remains unprivileged and does not install or activate units.
Systemd is an external host dependency (DEP-008); no libsystemd linkage or
redistributed systemd binary is introduced. Ubuntu 26.04 AMD64 is the target.

## Identity and boundary

`packaging/systemd/knetsentry.conf` declares the non-login `knetsentry` system
user/group, without supplementary groups or a usable home. The administrator
must ensure this is a dedicated identity, not a pre-existing unrelated account.
The unit runs entirely as that identity, with an empty capability bounding and
ambient set, no new privileges, no setuid/setgid changes, and no raw or IP socket
access (private network namespace and AF_UNIX-only address families).
The root-owned executable and launcher are not writable by the service.
Systemd runs the foreground daemon via a fixed launcher that uses `exec` so
SIGTERM reaches the actual manager. Type=exec confirms execution of the launcher,
not application readiness; the existing manager_ready event and successful
HEALTH exchange establish the latter. No automatic restart or enablement.

`/run/knetsentry` and `/var/lib/knetsentry` are systemd-managed 0700 directories.
The socket is 0600. Each start creates a fresh private audit session under the
state directory with the M2.5 exclusive 0600 JSONL file; audit is mandatory in
this profile and failure still exits 6. Old evidence is never rotated or deleted
by this implementation. The launcher selects built-in safe configuration only;
explicit system-service configuration provisioning is deferred (foreground
--config behavior is unchanged). No configuration or evidence path is derived
from a desktop request. No raw-event storage is provisioned.

The M2.3 matching UID/GID rule and M2.6 client verification are unchanged.
Ordinary desktop users are deliberately denied access to this dedicated service
(TB-05, I-01, KS-NET-012, TH-010/TH-011/TH-038, TV-27). Never add a desktop user
to the service identity or relax socket/directory permissions to work around
this. The existing same-user foreground manager and GUI remain available for
development. Future authenticated cross-identity roles require a new contract.

## Confinement and limits

ProtectSystem=strict makes the filesystem read-only except for systemd-managed
writable state/runtime and private temporary areas. ProtectHome, PrivateDevices,
PrivateTmp, ProtectProc, ProcSubset and the kernel/control-group/clock/hostname
protections reduce exposure. Namespace creation, SUID/SGID creation, personality
changes, writable-executable mappings and non-native syscall architectures are
restricted. No claims of a complete syscall allowlist or sandbox escape proof.
The provisional budgets are MemoryMax=128 MiB, TasksMax=16, CPUQuota=25% of one
CPU, LimitNOFILE=64 and LimitCORE=0. They are not measured production sizing.
Stop timeout is 10 seconds, startup command timeout 15 seconds; a stuck
filesystem may still delay shutdown. Journal output is the existing redacted
lifecycle diagnostics; audit records stay private (TB-07, TH-033).

## Explicit development deployment (fresh VM recommended)

Use a fresh Ubuntu 26.04 VM or approved development host. Do not overwrite an
existing service/account or installation; inspect any collision before proceeding.
Build `linux-release` first. From the repository root, as an ordinary user:

```bash
# Check for collisions; if any of these exist, stop and inspect them.
getent passwd knetsentry
getent group knetsentry
ls -ld /etc/systemd/system/knetsentry-manager.service /usr/local/libexec/knetsentry /var/lib/knetsentry
```

On a fresh host only, after reviewing the sources:

```bash
sudo systemd-sysusers packaging/systemd/knetsentry.conf
sudo install -d -o root -g root -m 0755 /usr/local/libexec/knetsentry
sudo install -o root -g root -m 0755 build/presets/linux-release/apps/manager/knetsentryd /usr/local/libexec/knetsentry/knetsentryd
sudo install -o root -g root -m 0755 packaging/systemd/manager-launcher /usr/local/libexec/knetsentry/manager-launcher
sudo install -o root -g root -m 0644 packaging/systemd/knetsentry-manager.service /etc/systemd/system/knetsentry-manager.service
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/knetsentry-manager.service
```

Do not enable the service for this test. The explicit live verifier starts and
stops only an inactive, disabled, exact installed unit (no drop-ins or pending reload),
checks the installed binary against the current build and requires a distinct
ordinary outsider account. It must not be run while another operator is managing
the unit. Review the verifier before executing it with administrator privileges.

```bash
sudo python3 -B scripts/check_m27_systemd_runtime.py --binary build/presets/linux-release/apps/manager/knetsentryd --outsider "$(id -un)"
```

It examines actual process identities, capabilities, NoNewPrivs, seccomp,
network/mount namespaces, mount permissions and cgroup/rlimit values; verifies
an authorized health query and a distinct ordinary user's filesystem denial;
then verifies clean stop, socket cleanup and ordered private audit evidence.
It does not print the audit records. A successful check is not a complete
adversarial sandbox test. The root administrator remains trusted. The private network namespace and
address-family filter do not prohibit all host pathname-based AF_UNIX services
that are otherwise accessible to the dedicated identity.
Afterwards the service is stopped and disabled (if it was never enabled), and
files/account/audit evidence remain for deliberate administrator review. To remove
only the installed executable/unit, stop the service if necessary and remove the
three explicitly installed files followed by daemon-reload; retain state and
account pending a separate evidence retention decision. Never recursively delete
state as a test cleanup. Aggregate disk quotas and retention remain future work.

## Qualification

`python3 scripts/verify_m27_systemd.py --systemd-parser` verifies exact source
policy, negative mutations and systemd parser syntax using a substitute executable
without installing anything. `knetsentry_systemd_policy_contract` is mandatory
in all seven presets; it does not start a unit or require privileges. Expected
counts: desktop 28/24 (normal/sanitized), core-only 18/19 (normal/sanitized).
The live test requires actual systemd PID 1, cgroup v2 and the target host;
parser success or ordinary CI does not qualify confinement. No independent
security audit or complete TV-27 closure is claimed.

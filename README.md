<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry

**Local Network Security Intelligence**

KnetSentry is a planned open-source, local-first Security Information and Event
Management (SIEM) platform for systems and security operators monitoring
**explicitly authorized devices on their own local networks**. Its intended
architecture combines a central management service, **first-class agentless
network sensors and gateway telemetry**, optional Ubuntu endpoint agents, a
security-event pipeline, detection and investigation tools, and optional
offline AI assistance.

> **Development status — M2.7 (systemd service hardening):**
> The repository contains a Qt-independent C++23 core, a seven-section Qt 6 /
> Kirigami desktop preview, privacy-bounded structured diagnostics, CTest and
> Qt Test suites, compiler hardening, sanitizers and **nine passing Ubuntu
> 26.04 GitHub Actions checks reported for M1.8**. The graphical interface is
> **not an operational SIEM**. A lifecycle-only manager with fail-closed v1 configuration and opt-in
> authenticated local status/health IPC, opt-in protected service audit logging and read-only desktop daemon health exist, but no agentless network sensor, host agent,
> event database, threat detection or privileged security controls exist yet.
> A green CI run validates only its documented tests, not release readiness.

The M1.4 follow-up includes a page-lifecycle warning regression test and an
optional, reversible [GNOME development desktop-entry helper](docs/development/GUI_NAVIGATION.md#desktop-portal-registration-on-gnome).

## Intended platform and architecture

- **Initial target:** Ubuntu 26.04 LTS on AMD64/x86-64, with support for both
  GNOME and KDE Plasma desktops.
- **Implementation:** C++23 (with narrowly justified C components), CMake,
  Ninja, and a modular service/agent architecture.
- **Desktop:** Qt 6, Qt Quick/QML, KDE Frameworks 6, and Kirigami. The desktop
  is unprivileged and communicates with the management service over authorized
  local IPC; security services do not depend on GUI libraries.
- **Monitoring:** Administrator-approved local networks can be monitored
  **without endpoint installations**, using passive sensors and available
  router, switch, access-point, DHCP, DNS, and firewall telemetry. Optional
  agents provide deeper host-specific evidence. Observed local devices may be
  inventoried under an approved network scope without individual enrollment.
  Available inbound/outbound Internet flows are in scope; external conversation
  peers are never automatically enrolled or probed.
- **Network access:** Agent/manager transport is locally scoped; optional,
  explicitly approved HTTPS access to CVE, MITRE ATT&CK, and other trusted
  intelligence sources is permitted through a restricted manager component.
  Private addresses alone are not proof of LAN membership.
- **AI:** Optional, offline and restricted to local inference; normal SIEM
  operation must not depend on a model or a cloud provider.

## Planned security workflow

1. An administrator authorizes one or more local network segments and
   configures a passive sensor, gateway export, or other legitimate telemetry
   source. **No agent is required on observed devices.**
2. The platform inventories visible LAN devices and analyzes observable flows,
   DNS events, device communication patterns, and available firewall/gateway
   records. Optional enrolled agents add host-level logs where supported.
3. The manager validates, normalizes, indexes, and retains selected events.
4. Deterministic rules and correlation logic generate traceable alerts.
5. An analyst investigates, records evidence, manages incidents, and exports
   reports. Offline AI may suggest summaries or investigative leads, but cannot
   independently take privileged response actions.

**Coverage is determined by network topology and sensor placement.** On a
switched or encrypted network, an ordinary workstation often cannot see
traffic exchanged by other devices. Comprehensive agentless monitoring may
require gateway logging, switch port mirroring, an authorized tap, or access
point/controller exports. KnetSentry must identify uncovered devices and
segments rather than claim complete visibility. Encrypted payloads are not
silently decrypted; local observed endpoints can be cataloged without an agent
under the approved network scope.

## Build and test the current graphical foundation

New contributors should follow the [Ubuntu 26.04 contributor quickstart](docs/development/CONTRIBUTOR_QUICKSTART.md), including its exact package list, test commands, GUI instructions and security-review steps. To build locally:

```bash
cmake --preset linux-release
cmake --build --preset linux-release --parallel
ctest --preset linux-release --output-on-failure
```

Running `./build/presets/linux-release/apps/desktop/knetsentry` opens the
Kirigami visual design and navigation shell. Use the global drawer or `Ctrl+1` through `Ctrl+7`
to select its seven pages. None monitor or collect traffic. `--version` and
`--help` work without a graphical display. `--self-test-qml` is used by the
mandatory `knetsentry_kirigami_qml_startup` CTest with an offscreen renderer.
The `knetsentry_primary_navigation` test verifies all seven routes without
creating simulated telemetry. See the [M1.4 navigation guide](docs/development/GUI_NAVIGATION.md)
and [M1.3 GUI foundation guide](docs/development/GUI_FOUNDATION.md).
`linux-sanitize` adds ASan/UBSan for project code. The `linux-core-only` preset
remains useful but **cannot qualify the Qt/Kirigami desktop**.

The M1.5 design system introduces platform-themed cards, severity examples
(never simulated alerts), consistent typography and spacing, and responsive
scrolling pages. See the [visual design system](docs/development/VISUAL_DESIGN_SYSTEM.md)
for the appearance/contrast and reduced-motion contracts. Qt/KDE light/dark
appearance follows the user's system palette; in-app theme switching is not
yet implemented. The offscreen `knetsentry_visual_system` test qualifies real
QML tokens in non-sanitized desktop builds.

## M1.6 structured application diagnostics

The Qt-independent core now provides an allowlisted, bounded JSON-line
publisher with severity, component, event, outcome, UTC epoch time, an
instance-local sequence, optional non-sensitive counts, and fixed redaction
of explicitly designated private context. The desktop emits fixed lifecycle
codes to stderr only; no telemetry or protected audit store is introduced.
See the [M1.6 structured diagnostics contract](docs/development/STRUCTURED_DIAGNOSTICS.md).
Validate with `python3 scripts/verify_m16_diagnostics.py` and the
`knetsentry_structured_diagnostics` CTest in each relevant preset.
Raw Qt/Kirigami framework output is **not** sanitized by this publisher.

The M1.8 CI follow-up preserves original SPDX declarations while preventing
licensing-verifier fixture strings from being misread as additional license
tags by the official REUSE scanner. Run `reuse lint` before merging; see
[CI implementation details](docs/development/CI_IMPLEMENTATION_M18.md).

## M1.7 foundational CTest and Qt Test suites

The test foundation now includes real Qt Test (`QAbstractItemModelTester`,
`QSignalSpy`, and `QProcess`) suites for a fixed, non-operational navigation
catalog and the existing desktop application, plus a Qt-independent C++
privacy regression and an executable CTest configuration/inventory gate.
The core-only presets remain Qt-independent; they **cannot** qualify the GUI.
All M1.7 tests use synthetic/fixed data, never live LAN telemetry.
See [M1.7 testing and acceptance](docs/development/TEST_SUITE_FOUNDATION.md).

## Product documentation

| Document | Purpose |
| --- | --- |
| [Contributor quickstart](docs/development/CONTRIBUTOR_QUICKSTART.md) | Clean Ubuntu 26.04 AMD64 build, CTest, REUSE and GUI reproduction steps |
| [M1.9 repository metadata audit](docs/development/REPOSITORY_METADATA_M19.md) | Existing licenses, templates and contributor policies; optional GitHub About metadata |
| [M1.9 CI efficiency](docs/development/CI_EFFICIENCY_M19.md) | Scoped runner packages, installed-package reuse and future caching risk |
| [M1.7 CTest and Qt Test foundation](docs/development/TEST_SUITE_FOUNDATION.md) | Compiled C++/Qt Test suites, CMake inventory gate, negative checks and acceptance commands |
| [M1.6 structured diagnostics](docs/development/STRUCTURED_DIAGNOSTICS.md) | Typed event catalog, redaction boundary, JSONL limits and test instructions |
| [M1.5 visual design system](docs/development/VISUAL_DESIGN_SYSTEM.md) | KDE/Qt palettes, severity/status separation, spacing, responsive UI and accessibility foundations |
| [M1.4 navigation shell](docs/development/GUI_NAVIGATION.md) | Seven Qt/Kirigami top-level destinations, navigation testing, and honest placeholder state |
| [M1.2 compiler hardening](docs/development/HARDENING_AND_ANALYSIS.md) | Target-scoped compiler warnings, sanitizers, optional analysis and ELF verification |
| [M1.1 build foundation](docs/development/BUILD_FOUNDATION.md) | CMake presets, dependency setup, smoke tests, target ownership |
| [Product vision](PRODUCT_VISION.md) | Purpose, audiences, benefits, success criteria, and non-goals |
| [Product scope](docs/architecture/PRODUCT_SCOPE.md) | Supported deployments, boundaries, capabilities, and exclusions |
| [Modular system architecture](docs/architecture/SYSTEM_ARCHITECTURE.md) | Process separation, data flows, privileges, and module dependencies |
| [Component and process catalog](docs/architecture/COMPONENT_CATALOG.md) | 21 component responsibilities and 12 process roles |
| [Interface contracts](docs/architecture/INTERFACE_CONTRACTS.md) | 23 planned logical handoffs, input trust, and fail-closed semantics |
| [Deployment topologies](docs/architecture/DEPLOYMENT_TOPOLOGIES.md) | Agentless and optional agent deployment/visibility profiles |
| [Architecture traceability](docs/architecture/ARCHITECTURE_TRACEABILITY.md) | Ownership of 12 threat boundaries, 42 threats, and 42 network requirements |
| [Architecture decisions](docs/architecture/adr/0001-security-process-boundaries.md) | Recorded choices for privilege separation, evidence, egress, and Qt |
| [Security principles](docs/security/SECURITY_PRINCIPLES.md) | Trust model, mandatory controls, and security requirements |
| [Network scope requirements](docs/security/NETWORK_SCOPE_REQUIREMENTS.md) | Distinct monitoring, transport, and external-intelligence security boundaries |
| [Network communication matrix](docs/architecture/NETWORK_COMMUNICATION_MATRIX.md) | Intended permitted, observed, and prohibited flows |
| [Network verification plan](docs/security/NETWORK_SCOPE_VERIFICATION_PLAN.md) | Future M3 and integration test specifications |
| [Initial threat model](docs/security/THREAT_MODEL.md) | Protected assets, adversaries, trust boundaries, attack scenarios, limits |
| [Threat register](docs/security/THREAT_REGISTER.md) | Qualitative risk screening, proposed controls, future owners |
| [Threat verification matrix](docs/security/THREAT_VERIFICATION_MATRIX.md) | Planned tests and evidence needed for future security claims |
| [Release objectives](docs/development/RELEASE_OBJECTIVES.md) | v1.0.0 release bar, milestone groups, and open decisions |
| [Secure development contract](DEVELOPMENT_CONTRACT.md) | 40 staged coding, security, testing and release requirements |
| [Secure coding standard](docs/development/SECURE_CODING_STANDARD.md) | C++23, Qt/QML, input, privilege and concurrency rules |
| [Toolchain and testing plan](docs/development/TOOLCHAIN_TEST_MATRIX.md) | Current compiler/sanitizer gates and planned Qt, CI and fuzzing checks |
| [CI security policy](docs/development/CI_SECURITY_POLICY.md) | PR isolation, action pinning, minimal permissions and progressive checks |
| [Verification matrix](docs/development/VERIFICATION_MATRIX.md) | 30 future gate identifiers, owners and evidence conditions |
| [Security review procedure](docs/development/SECURITY_REVIEW_PROCESS.md) | Threat-boundary impact and exception handling |
| [Evidence format](docs/development/VERIFICATION_EVIDENCE.md) | PASS/FAIL/BLOCKED reporting and redacted reproducible results |
| [Performance requirements](docs/development/PERFORMANCE_REQUIREMENTS.md) | 54 initial engineering requirements and measurement definitions |
| [Workload profiles](docs/development/WORKLOAD_PROFILES.md) | Synthetic agentless and optional-agent benchmark cases W-00–W-09 |
| [Benchmark plan](docs/development/BENCHMARK_PLAN.md) | 28 prospective benchmark cases and evidence methodology |
| [Storage placement contract](docs/architecture/STORAGE_PLACEMENT_CONTRACT.md) | Administrator-selected raw drive, raw-first writes, separate indexes and mount safety |
| [Storage/capacity model](docs/development/RESOURCE_CAPACITY_MODEL.md) | Honest data-size calculations, process budgets, and retention limits |
| [Recovery plan](docs/development/RELIABILITY_RECOVERY_PLAN.md) | 18 planned outage and degradation cases |
| [Result template](docs/development/BENCHMARK_RESULT_TEMPLATE.md) | Required future benchmark provenance and observations |

The GitHub roadmap covers M0–M15 for v1.0.0, followed by a separate optional
M16 milestone for KDE community adoption. Following KDE development guidance
does **not** imply that KnetSentry is an official KDE project.

## Development and contributions

The repository now has compiled C++/Qt Test suites and successful M1.8
GitHub-hosted CI checks, but the operational SIEM remains unimplemented.
Start with the [contributor quickstart](docs/development/CONTRIBUTOR_QUICKSTART.md)
and [CONTRIBUTING.md](CONTRIBUTING.md). Use the accepted PR template,
security-review guidance, official REUSE lint, and actual CTest results.
The maintainer reports that private vulnerability reporting is enabled;
GitHub's current private-advisory availability and branch rules are separate
platform settings, not automatically enforced by documentation.

## Project governance and security reports

[Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Security policy](SECURITY.md) · [Governance](GOVERNANCE.md) · [Repository setup checklist](docs/development/REPOSITORY_ADMIN_CHECKLIST.md).

**Do not publish vulnerabilities or private LAN evidence in public issues.** Security
reports should use GitHub private advisories; verify the reporting button
before submitting sensitive details. KnetSentry is not yet an official KDE project.

## License

KnetSentry-authored application code and tooling use **MIT**; the original
[root MIT license](LICENSE) is unchanged. Revised project documentation uses
**CC-BY-SA-4.0** under per-file SPDX headers. Future custom CMake code will
use **BSD-2-Clause**. Earlier MIT grants to documents remain valid.

See the [licensing policy](docs/development/LICENSING_POLICY.md),
[dependency approval process](docs/development/DEPENDENCY_APPROVAL_POLICY.md),
[initial candidate register](docs/development/DEPENDENCY_REGISTER.md),
[third-party notice policy](docs/development/THIRD_PARTY_NOTICE_POLICY.md), and
[KDE compatibility policy](docs/development/KDE_COMPATIBILITY_POLICY.md).
M0.6 records policies; it does **not** approve Qt modules, bundled libraries,
third-party detection corpora, AI weights, or any release distribution.

## M1.8 CI acceptance and M1.9 efficiency

The [CI implementation guide](docs/development/CI_IMPLEMENTATION_M18.md)
documents the read-only Ubuntu 26.04 GitHub Actions matrix. The maintainer
reports **nine successful M1.8 PR checks**, including seven build/test lanes,
policy/REUSE, and QML lint. Whether all nine are configured as *required*
branch-protection checks still requires separate GitHub settings verification.

M1.9 reduces unnecessary runner provisioning with explicit dependency profiles:
core-only jobs do **not** install Qt/Kirigami, and installed packages are not
reinstalled. No shared binary or privileged APT cache is introduced. See
[CI efficiency and cache decision](docs/development/CI_EFFICIENCY_M19.md).
The maintainer reported nine passing M1.9 PR checks; the core-only lane
completed in approximately 19 seconds, down from about ten minutes in M1.8.

## M2.1 management daemon lifecycle

The new **unprivileged, Qt-independent** `knetsentryd` executable implements
explicit service states and graceful SIGINT/SIGTERM shutdown. It runs in the
foreground, refuses root execution, and emits only allowlisted M1.6 lifecycle
diagnostics. At M2.1 there were **no sockets, IPC APIs, packet capture, databases, or
security monitoring functions**. The GUI remains a separate process.
See [M2.1 daemon contract](docs/development/MANAGER_DAEMON_M21.md).

```bash
cmake --preset linux-release --fresh
cmake --build --preset linux-release --parallel
ctest --preset linux-release --output-on-failure
./build/presets/linux-release/apps/manager/knetsentryd --help
./build/presets/linux-release/apps/manager/knetsentryd
# Stop with Ctrl+C. Do not launch as root.
```

Expected M2.1 CTest totals: desktop **15**, full sanitizer **12**, core-only
**7**, core-only sanitizer **8**. These counts require actual local and hosted
execution before acceptance.

## M2.2: secure manager configuration

The standalone manager now supports strict schema v1 configuration validation
without Qt/Kirigami. See the [configuration guide](docs/development/MANAGER_CONFIGURATION_M22.md)
and [safe example](examples/manager-v1.conf). Explicit configuration errors
are rejected with no fallback or operational monitoring.

### M2.3 — Authenticated local IPC foundation

`knetsentryd` optionally supports a **Unix-domain socket** via `--ipc-dir ABS_DIR`
(an existing 0700 directory owned by the daemon user). The socket is 0600;
Linux `SO_PEERCRED` plus an explicit allowlist originally authorized a bounded,
read-only lifecycle-status request from the same UID/GID. No administrative
methods, remote listeners, telemetry or monitoring are enabled. See the
[M2.3 local IPC contract](docs/development/LOCAL_AUTHENTICATED_IPC_M23.md).

### M2.4 — Service health and diagnostics

The opt-in local IPC endpoint also supports the read-only `HEALTH` operation.
It reports actual monotonic uptime, cumulative process CPU time, peak resident
memory, configuration and IPC status, explicit monitoring unavailability, and
bounded operational error counts. It preserves the original `STATUS` wire
response and peer authorization. See the [M2.4 health contract](docs/development/SERVICE_HEALTH_M24.md)
for units, framing, verification and limitations. No monitoring or GUI health
polling is enabled by this change.

### M2.5 — Structured service audit logging

Use `--audit-dir ABS_DIR` with a fresh owner-only directory to enable the
bounded persistent audit sink. See the [M2.5 audit contract](docs/development/SERVICE_AUDIT_M25.md)
for scope, activation, privacy, failure behavior and limitations.

### M2.6 — Desktop management health

The desktop optionally queries the manager's authorized HEALTH interface. Start
the manager with an existing mode-0700 private IPC directory, then use the same
absolute directory with `knetsentry --ipc-dir ABS_DIR`. Without that option
the GUI makes no service requests. See the [M2.6 desktop health contract](docs/development/DESKTOP_HEALTH_M26.md)
for connection, disconnection, bounded polling and audit-budget implications.

### M2.7 — Hardened systemd manager deployment

The [systemd service contract](docs/development/SYSTEMD_SERVICE_M27.md)
provides an explicit administrator-installed development service using a
non-login dedicated identity, no capabilities, private runtime/audit paths,
network and filesystem isolation, and finite resource limits. The current
same-UID desktop development IPC remains separate; ordinary desktop users
cannot access the installed system service. No service is installed or enabled
by a normal build. Live systemd qualification is required on Ubuntu 26.04.

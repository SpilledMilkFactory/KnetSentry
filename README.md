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

> **Development status — M1.4 (Qt Quick/Kirigami primary navigation):**
> The repository includes a Qt-independent C++23 core, CMake/Ninja presets,
> compiler hardening, ASan/UBSan, the M0 documentation contracts and a real
> **Qt 6/Kirigami desktop shell** with seven navigable sections (Dashboard,
> Assets, Events, Detections, Alerts, Investigations, and Settings). Every
> section explicitly reports monitoring is **not active**. No management daemon, agentless network sensor, detection
> engine, alerting, or privileged security controls are implemented yet.
> The Qt QML startup smoke test validates actual Kirigami imports; it is not a
> security or production qualification.

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

## Building the M1.6 diagnostics-enabled visual shell

On Ubuntu 26.04 AMD64, install the [build prerequisites](docs/development/BUILD_FOUNDATION.md), then run:

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

The repository is in its documentation-first foundation stage. Build commands,
source-code test suites and CI workflows will be implemented in their scheduled
milestones. M0.8 adds governance and public issue/PR templates; **private vulnerability
reporting must still be enabled and verified in GitHub settings**. M0.7 documents the
[development contract](DEVELOPMENT_CONTRACT.md) but has not executed
compiler, Qt, sanitizer, network or runtime tests; never infer that a missing
test has passed.

For now, review the requirements documents above and file GitHub issues for unclear,
conflicting, or untestable requirements. Security-sensitive implementation
should not begin until its relevant trust and network boundaries are defined.

## Project governance and security reports

[Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Security policy](SECURITY.md) · [Governance](GOVERNANCE.md) · [Repository setup checklist](docs/development/REPOSITORY_ADMIN_CHECKLIST.md).

**Do not publish vulnerabilities or private LAN evidence in public issues.** Security
reports use GitHub private advisories when explicitly enabled; see the security
policy for the current setup limitation. KnetSentry is not yet an official KDE project.

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

## M1.8 — Ubuntu 26.04 CI candidate

The new [CI implementation guide](docs/development/CI_IMPLEMENTATION_M18.md) describes the read-only Ubuntu 26.04 GitHub Actions matrix and security-policy checks. **Hosted checks and branch protection remain unverified until executed/configured on GitHub.**

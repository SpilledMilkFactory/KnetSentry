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

> **Development status — M0.5 (design documents only):** This repository
> contains the product and network-security contracts, threat model, modular
> architecture, and initial performance/reliability qualification targets.
> It does **not** yet include a
> functional SIEM, network collector, desktop application, detection engine, or
> production security controls. The capabilities below are *planned*, not
> implemented or security-certified.

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

## Product documentation

| Document | Purpose |
| --- | --- |
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
contributor instructions, automated tests, and security disclosure workflows
will be added in their scheduled milestones; do not infer that a missing test
has passed.

For now, review the requirements documents above and file GitHub issues for unclear,
conflicting, or untestable requirements. Security-sensitive implementation
should not begin until its relevant trust and network boundaries are defined.

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

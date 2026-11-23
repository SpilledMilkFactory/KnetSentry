<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry — Product Scope and Deployment Boundaries

**Status:** M0.1 product baseline refined by M0.2 network requirements.
M0.3–M0.4 will specify the threat model and detailed service interfaces;
no network security implementation is implied here.

## 1. Initial compatibility contract

| Concern | Initial scope |
| --- | --- |
| Management and agent hosts | Ubuntu 26.04 LTS, AMD64/x86-64 |
| Desktop environments | GNOME and KDE Plasma on the supported OS |
| Desktop stack | Qt 6, Qt Quick/QML, KDE Frameworks 6, Kirigami |
| Services | Modern C++23, narrowly justified C, CMake + Ninja |
| Monitoring scope | Administrator-approved LAN segments and sensor sources; agentless device observation is first-class |
| Transport scope | Authenticated agent/manager communication on approved LAN paths |
| Internet intelligence | Optional, administrator-approved HTTPS feed synchronization; not required for core monitoring |
| GUI dependency of services | None; security processes run without a desktop |

Passive sensors, local gateway exports, and authorized device-log integrations
may observe non-Ubuntu equipment (printers, doorbells, cameras, smart TVs)
**without installing an agent on those devices**. The supported Ubuntu target
applies to KnetSentry's own executable components, not to the observed devices.

## 2. Deployment roles

**Manager (`knetsentryd`, planned):** Maintains approved configuration and agent
identity state; receives, validates, and processes authorized telemetry; stores
and searches security information; evaluates rules; manages alerts and
incidents; and exposes an authenticated local control plane.

**Endpoint agent (`knetsentry-agent`, planned):** Runs on an enrolled Ubuntu
system; collects only approved host evidence through restricted collectors;
buffers and forwards selected telemetry over authenticated, encrypted,
in-scope transport.

**Desktop (`knetsentry`, planned):** Provides security operations dashboards,
assets, events, detections, alerts, investigations, and settings via authorized
local IPC. The GUI is unprivileged and does not directly query protected host
resources or bypass manager authorization. Services work without the GUI.

**CLI (`knetsentryctl`, planned):** Offers narrow administrative interfaces
subject to the same authentication, authorization, and auditing rules.

**Agentless sensor / gateway ingest (planned baseline):** Observe authorized
local traffic via supported passive capture, mirrored ports, and/or gateway,
firewall, access-point, DHCP/DNS, and network-flow exports. Source trust,
coverage, and telemetry content are documented; no software is required on
observed IoT devices.

**Optional integrations (planned):** Host-level endpoint agents, additional
network-device log sources, isolated offline AI, and manager-controlled public
security-intelligence feeds, each with its own privacy, authorization,
provenance, and resource controls.

## 3. Monitoring and network-communications contract

1. Monitor devices observed within **administrator-approved LAN segments**
   using authorized passive sensors or network exports, without requiring
   per-device approval or agents. Authorized telemetry may include traffic
   exchanged between local assets and **external Internet peers**. Unknown
   devices can be identified and alerted on, not automatically trusted.
2. Remote addresses appearing in network events do not become monitored hosts
   or authorized targets for active scanning, probing, DNS queries, or fetches.
3. Secure agent-to-manager communications use administrator-approved local
   interfaces, segments, peer identities, and host-enforced policies.
4. Default transport scope is on-link; additional routed local VLANs/subnets
   require specific administrative authorization and validated paths. Unapproved
   VPNs, tunnels, routes, and interfaces are denied.
5. A designated manager component **may** fetch public CVE, MITRE ATT&CK, KEV,
   and other approved intelligence over HTTPS when individually configured.
6. External feed traffic is restricted by provider, purpose, endpoint, TLS,
   redirect, DNS and privacy rules. No automatic upload of private telemetry.
7. The GUI, agent collectors, and optional AI inference do not inherit general
   Internet access. Core SIEM operation remains functional offline.
8. IPv4/IPv6 scope, interface and route changes, authorization, and firewall
   enforcement must fail closed for the affected operation.
9. Application policy and Linux host-enforcement tests are scheduled in M3;
   publishing these requirements does not constitute enforcement.

See the authoritative [network contract](../security/NETWORK_SCOPE_REQUIREMENTS.md),
[flow matrix](NETWORK_COMMUNICATION_MATRIX.md), and
[future verification plan](../security/NETWORK_SCOPE_VERIFICATION_PLAN.md).

## 4. Planned in-scope functionality

### Security telemetry

- **First-class agentless monitoring** of local devices within approved
  network/sensor scope using visible flow, DNS, DHCP, firewall, or passive
  capture metadata. No software installation on doorbells, printers, or IoT
  equipment is required.
- Supported gateway/router exports, network-device syslog, and selected
  passive capture modes, with explicit source, coverage, and trust limitations.
- **Optional** authenticated agent enrollment and systemd journal,
  authentication, SSH, Linux Audit Framework, and file-integrity event
  collection on approved Ubuntu hosts.
- Asset inventory derived from available network evidence and/or authorized
  agent identities; unknown devices may be identified passively but accuracy
  and full coverage are not presumed.

### Processing and investigations

- Bounded event ingestion, normalization aligned to a pinned OCSF profile,
  source attribution, configurable retention, indexed search, and original
  evidence preservation where configured.
- Deterministic detection rules, alerts, suppression, temporal/cross-host
  correlation, justified MITRE ATT&CK mappings, and analyst-facing timelines.
- Incident case management, evidence integrity metadata, reports, and narrow,
  explicitly approval-gated response designs.

### Operator experience

- Qt Quick/Kirigami dashboards, visualizations, asset views, investigation
  interfaces, saved searches, and reporting.
- Optional offline AI summaries and recommendations that neither supersede
  evidence nor independently authorize privileged operations.

## 5. Initial non-goals and exclusions

- Unapproved active scanning, probing, interception, or collection outside the
  network owner's authorized monitoring scope. Passive discovery and inventory
  of local devices within an approved sensor scope are **not excluded**.
  Future opt-in active local discovery must be separately approved, bounded,
  and confined to authorized segments.
- Cloud hosting, cloud inference, unapproved Internet telemetry upload,
  external account services, arbitrary external queries, or silent background
  feed connections. Approved HTTPS security-intelligence synchronization is
  optional and separately governed by administrator policy.
- Windows or non-Ubuntu endpoint agents, ARM targets, enterprise distributed
  clusters, or additional supported OS packages in v1.0.0.
- Guaranteed complete visibility where the network does not supply traffic
  to the sensor; successful plaintext inspection of encrypted sessions; precise
  firmware/CVE attribution without corroborating inventory; causation from
  correlation; or lossless operation under all failures.
- Unrestricted automated remediation or AI-directed administrative actions.
- Official KDE affiliation before its independent community review process.

## 6. Trust and observability limits

Authenticated agents can still be compromised; records can be missing,
misleading, delayed, or attacker-controlled. Integrity hashes can help detect
specific post-collection changes but cannot prove the original report was
truthful. Detection explanations and reports must preserve those limitations.

## 7. Unresolved decisions

M0.2 defines the monitoring, local transport, and optional intelligence-egress
contracts. M0.3 supplies the threat model. M0.4 formalizes service interfaces,
process boundaries, and protocols.
M0.5 defines performance and capacity thresholds. M0.6 resolves the final
licensing, dependency, and KDE compliance policy.

Any proposed expansion of collection or network scope needs a reviewed change
rather than silently appearing through feature implementation.

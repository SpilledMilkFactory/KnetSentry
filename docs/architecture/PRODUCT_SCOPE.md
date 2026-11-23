<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry — Product Scope and Deployment Boundaries

**Status:** M0.1 product boundary statement. Detailed policies will be specified
in M0.2–M0.4; no security implementation is implied here.

## 1. Initial compatibility contract

| Concern | Initial scope |
| --- | --- |
| Management and agent hosts | Ubuntu 26.04 LTS, AMD64/x86-64 |
| Desktop environments | GNOME and KDE Plasma on the supported OS |
| Desktop stack | Qt 6, Qt Quick/QML, KDE Frameworks 6, Kirigami |
| Services | Modern C++23, narrowly justified C, CMake + Ninja |
| Connectivity | Administrator-approved local interfaces, destinations, and peers |
| Internet dependency | None for normal KnetSentry operation |
| GUI dependency of services | None; security processes run without a desktop |

Device integrations that accept syslog or optional passive observations may
receive data from non-Ubuntu network equipment. This **does not imply** that
KnetSentry's endpoint agent runs on such devices.

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

**Optional integrations (planned):** Explicitly configured network-device log
sources, passive sensors, and isolated offline AI, each with its own privacy,
privilege, provenance, and resource controls.

## 3. LAN-only contract

1. KnetSentry processes **must not initiate Internet connections**, including
   cloud AI, update checks, analytics, crash uploads, or external lookups.
2. Connections must be approved by a network-scope policy and independently
   constrained through supported operating-system controls.
3. Administrators must explicitly approve interfaces, destinations, and
   networks. RFC 1918, link-local, loopback, or globally scoped addresses do
   not automatically become authorized merely by their address category.
4. Both IPv4 and IPv6 must be handled, including address-family transitions,
   IPv4-mapped addresses, and interface-scoped IPv6 link-local addresses.
5. Unexpected address, route, or interface changes require revalidation;
   uncertainty or failed policy checks must fail closed.
6. Routed VLANs, new subnets, VPNs, bridges, and virtual interfaces require
   an explicit M0.2 policy decision rather than default inclusion.
7. Local presence does not establish trust. Supported agent identities require
   explicit enrollment, validated authentication, and authorization.
8. Passive monitoring and network-device integration require specific
   authorization and must not enable unrestricted scanning or interception.
9. Application policy, firewall enforcement, and isolated-network adversarial
   tests will be developed in M3—not claimed as present in M0.1.

This contract governs **KnetSentry-originated communications**, not the
operating system's package manager or unrelated applications.

## 4. Planned in-scope functionality

### Security telemetry

- Authenticated agent enrollment and selected systemd journal, authentication,
  SSH, Linux Audit Framework, and file-integrity event collection on approved
  Ubuntu hosts.
- Configured network-device syslog and optional passive traffic *metadata*
  sources, with clear data-source and trust limitations.
- Asset inventory derived from authorized identities and observations—not an
  assertion of complete knowledge of all LAN devices.

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

- Automatic discovery, probing, or scanning of unknown LAN hosts, arbitrary
  packet interception, or monitoring without the network owner's authority.
- Cloud hosting, cloud inference, Internet telemetry upload, external account
  services, or default public threat-intelligence lookups.
- Windows or non-Ubuntu endpoint agents, ARM targets, enterprise distributed
  clusters, or additional supported OS packages in v1.0.0.
- Guaranteed visibility into non-enrolled devices, attack attribution,
  accurate causality from correlation, or lossless operation under all failures.
- Unrestricted automated remediation or AI-directed administrative actions.
- Official KDE affiliation before its independent community review process.

## 6. Trust and observability limits

Authenticated agents can still be compromised; records can be missing,
misleading, delayed, or attacker-controlled. Integrity hashes can help detect
specific post-collection changes but cannot prove the original report was
truthful. Detection explanations and reports must preserve those limitations.

## 7. Unresolved decisions

M0.2 specifies the precise network-scope policy. M0.3 supplies the threat
model. M0.4 formalizes service interfaces, process boundaries, and protocols.
M0.5 defines performance and capacity thresholds. M0.6 resolves the final
licensing, dependency, and KDE compliance policy.

Any proposed expansion of collection or network scope needs a reviewed change
rather than silently appearing through feature implementation.

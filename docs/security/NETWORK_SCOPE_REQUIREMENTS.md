<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Network Monitoring and Communications Security Contract

**Status:** M0.2 normative requirements; M3.1–M3.4 application-layer preflight
implemented (live IP enforcement not qualified). See the
[M3.1 policy contract](../development/NETWORK_SCOPE_POLICY_M31.md).
M3.2 extends that preflight with strict dual-stack prefix validation; see
[the M3.2 validation contract](../development/NETWORK_SCOPE_VALIDATION_M32.md).
M3.3 adds read-only Linux topology inspection and invalidation; see
[the M3.3 topology contract](../development/NETWORK_TOPOLOGY_M33.md).
M3.4 adds explicit fail-closed configuration and revision activation,
owned interface bindings and withdrawal on topology uncertainty; see
[the M3.4 authorization contract](../development/NETWORK_AUTHORIZATION_M34.md).
Operational IP transport and OS enforcement remain unqualified.
**Target:** Ubuntu 26.04 LTS AMD64; proposed v1.0.0 product architecture.
**Traceability:** GitHub issue #2 / M0.2.
**See also:** [network communication matrix](../architecture/NETWORK_COMMUNICATION_MATRIX.md),
[network verification plan](NETWORK_SCOPE_VERIFICATION_PLAN.md), and
[initial threat model](THREAT_MODEL.md).

## 1. Normative terms and distinct trust boundaries

**MUST/MUST NOT** are mandatory release requirements; **SHOULD** identifies
recommended controls whose exceptions require review. Every numbered
`KS-NET-###` requirement has future verification coverage. This contract is
not a promise that any network isolation feature already exists.

**Three independent boundaries are required:**

1. **Monitoring scope:** Whose systems and network activity may be observed?
   Administrator-approved LAN **network segments and sensor observation
   scopes**, including previously unknown local devices passively visible
   there. Explicit per-device approval or installed endpoint agents are
   **not** required for passive network observation; privileged access and
   agent enrollment require separate authorization. An external conversation
   peer appearing in *locally acquired* traffic is not a locally monitored
   asset.
2. **Collection/control-plane transport:** Which endpoints may exchange telemetry
   and management messages? The agent-to-manager channel is local-network
   scoped, individually authenticated, encrypted, and independently authorized.
3. **Security-intelligence egress:** Which external information sources may the
   manager query for defensive context? Approved HTTPS endpoints may be reached
   for CVE/vulnerability data, MITRE ATT&CK updates, CISA KEV, approved feeds,
   and vetted software update metadata. This is **not** permission to send
   telemetry, inspect third-party systems, or run arbitrary network clients.

The term *LAN* means the administrator's explicitly approved local network
segments and devices, rather than an entire RFC 1918 address range or every
address reachable via the Internet. LANs can include approved VLANs and locally
routed subnets; on-link connectivity is a safe initial default, **not an
immutable requirement that the entire LAN must share one Layer-2 segment**.

## 2. Monitoring-source authorization

| ID | Mandatory requirement |
| --- | --- |
| `KS-NET-001` | A local administrator MUST approve monitoring **network segment(s), sensors, and source interfaces** before data collection. Within that approved passive scope, previously unknown LAN devices MAY be discovered and monitored **without individual approval or endpoint software**; elevated access, agent installation, and control operations remain separately authorized. |
| `KS-NET-002` | **Host-internal** telemetry requires a voluntarily enrolled, authenticated agent or equivalent authorized host integration. Passive **network** telemetry does not require endpoint enrollment, software, credentials, or a trusted local device identity. An observed MAC/IP is evidence, not authorization for control-plane access. |
| `KS-NET-003` | Passive capture, local network export, and network-device logs MUST remain within administrator-approved interfaces and scope with data-minimization controls. No unrelated wide-area capture or unapproved active/intrusive probing; passive identification of unknown devices within the approved LAN is allowed. |
| `KS-NET-004` | Traffic **to or from an authorized LAN machine** may be analyzed whether its remote peer is local or on the public Internet, if observed through an approved endpoint or sensor. Remote address information is observational evidence, not automatic permission to contact the remote system. |
| `KS-NET-005` | Monitoring must not claim visibility into packets or processes not available from the selected collector. Switched LANs, encryption, NAT, and asymmetric routing can limit observations. No unauthorized decryption or man-in-the-middle interception. |
| `KS-NET-006` | All monitoring and network data must have source provenance, scope association, acquisition time, and confidence/limitations. Data originating outside authorized capture scope must be rejected or explicitly quarantined as appropriate. |
| `KS-NET-007` | Approved local IPv4 or IPv6 host addresses must be evaluated against administrator configuration and validated network attachment, **not** assumed valid/invalid solely because they are RFC 1918, IPv4 public, IPv6 ULA, IPv6 global unicast, or link-local. |

Examples: An enrolled workstation at `192.168.50.11` contacting a public IP
may produce a valid outbound flow record. A public IP *on an approved local host*
may be authorized when its device identity, location, and route are verified.
Neither fact grants KnetSentry authority to probe unrelated external hosts.

## 2A. Agentless network monitoring and IoT coverage requirements

These controls are mandatory for the v1.0.0 agentless monitoring profile.
`KS-NET-031`–`KS-NET-042` extend the original M0.2 requirement numbering
without renumbering the agent, intelligence, and enforcement requirements.

| ID | Mandatory requirement |
| --- | --- |
| `KS-NET-031` | An **agentless network monitoring mode MUST be an independently usable core SIEM capability**. It MUST accept legitimate network/gateway telemetry for authorized local devices regardless of operating system or ability to install an agent (e.g., printers, smart doorbells, cameras, smart TVs). Optional agents MAY enrich the evidence but MUST NOT be a prerequisite for baseline network alerts and investigations. |
| `KS-NET-032` | An administrator MAY authorize a **whole local segment, VLAN, or defined sensor observation domain** for passive network monitoring. Once approved, new/unknown local devices observed inside that scope MAY be automatically inventoried and generate alerts without individual enrollment; such observation MUST NOT grant device management access, trust, or permission to observe unrelated networks. |
| `KS-NET-033` | Supported agentless data sources MUST be explicitly identified and validated: appropriate passive packet/mirror/tap observation, gateway/firewall logs, flow exports, DHCP/DNS records, network-device syslog, and AP/controller telemetry **where available**. Configuration MUST distinguish available, unavailable, and non-authoritative sources; support is capability-specific, not universal router compatibility. |
| `KS-NET-034` | The system MUST NOT claim full LAN visibility without demonstrated sensor access. Normal switched Ethernet, isolated Wi-Fi clients, VLAN partitioning, NAT, asymmetric routes, mirror oversubscription, and encryption can create blind spots. Sensors MUST report observed interfaces, source capabilities, known coverage gaps, and lost/dropped records where measurable. |
| `KS-NET-035` | Sensor collection MUST record only actually observable protocol/flow data. Encrypted HTTPS, QUIC, or other protected sessions cannot be claimed to expose application payloads. Decryption, MITM, ARP spoofing, traffic diversion, or intrusive active discovery MUST NOT be enabled or attempted by default. |
| `KS-NET-036` | Asset attribution MUST account for IP reassignment, DHCP lease times, IPv6 privacy addressing, NAT, MAC randomization/spoofing, and shared devices. Attribute events using available evidence with explicit confidence and uncertainty; a vendor OUI or observed IP alone MUST NOT be treated as a verified device identity. |
| `KS-NET-037` | Agentless detections MUST support reproducible security alerts derived from legitimately observed traffic, including new local devices, unusual destinations/ports, anomalous communication rates, beacon-like behavior, unexpected lateral connections, or known-bad indicators when validated intelligence is available. Alerts MUST retain supporting telemetry and limitations. |
| `KS-NET-038` | Unknown devices observed in an administrator-approved segment MUST be distinguishable from approved administrative agents and trusted infrastructure. Passive discovery or inventory MUST NOT automatically enroll a device, authenticate it, or confer control-plane privileges. |
| `KS-NET-039` | Any future **active local device discovery** MUST be separately administrator-enabled, scope-constrained, rate-limited, auditable, and evaluated for fragile IoT devices. Active probing unrelated public Internet hosts remains prohibited. No scanning is required for passive-only monitoring. |
| `KS-NET-040` | The Qt operator interface MUST distinguish **observed assets, inferred assets, unobserved address space, and unavailable telemetry**. It MUST expose sensor position, coverage health, missing data, and confidence; it MUST NOT use an unqualified 'all endpoints protected' status. |
| `KS-NET-041` | Capture and network-ingestion components MUST use least privilege, narrow access to configured interfaces, bounded buffers/packet processing, and privacy-preserving retention. Raw packet payload retention MUST require separate explicit configuration and security review, with controls on access and retention. |
| `KS-NET-042` | Vulnerability findings for agentless IoT assets MUST distinguish confirmed vendor/model/firmware evidence from heuristics. CVE applicability MUST NOT be declared certain solely from MAC OUI, IP address, DNS name, or an unrelated vulnerability-feed match. |

**Deployment examples:** a home router that exports useful firewall/DHCP/DNS
records can provide network observations without any installed endpoint agent;
a managed switch mirror or network tap can supply additional passive flow
metadata to a sensor host. A plain Ubuntu desktop on an ordinary switched
port generally **cannot** observe the unicast exchanges of other ports and
is not sufficient by itself to guarantee whole-LAN coverage. These are
required product-support scenarios; hardware compatibility and packet-source
access must be tested, not assumed.

## 3. Agent, manager, and local control communications

| ID | Mandatory requirement |
| --- | --- |
| `KS-NET-008` | Enrolled agent transport is limited to approved manager identities, services, destination addresses, and interfaces; the reverse direction is limited to protocol-required return traffic unless separately approved. |
| `KS-NET-009` | Default deployment permits explicitly authorized on-link IPv4/IPv6 peers. Additional locally routed LAN subnets or VLANs require explicit administrative scope, topology/route validation, authenticated endpoint identity, and reviewed host rules; no blanket permission for default-gateway destinations. |
| `KS-NET-010` | Reject unauthorized tunnels, VPN/overlay links, dynamic remote brokers, wildcard listeners, and arbitrary Internet-based collectors. Unapproved new interfaces or subnets must not be included automatically. |
| `KS-NET-011` | Agent/manager transport must use mutually authenticated encrypted connections and enforce certificate lifecycle and endpoint authorization (protocol details are addressed in M0.4/M4). LAN residence alone never replaces identity checks. |
| `KS-NET-012` | The Qt desktop and `knetsentryctl` use authorized local IPC for management, not an exposed Internet-facing GUI or HTTP control endpoint; neither receives unrestricted privileged or network access. |
| `KS-NET-013` | Address checks must correctly handle IPv4/IPv6 dual stack, IPv4-mapped IPv6, interface-scoped IPv6 link-local, address normalization, loopback, multicast, and unknown address families. No bypass through alternative textual encodings. |
| `KS-NET-014` | A denied endpoint, ambiguous route, interface replacement, unapproved subnet, certificate failure, firewall installation failure, or unknown policy state must fail closed for the affected **agent/control-plane** operation. Other authorized collection and offline analysis may continue when safe. |
| `KS-NET-015` | Network scope and enforcement must be revalidated on interface/address/route changes, DHCP/SLAAC changes, VLAN/namespace transitions, policy revision, and firewall changes. Existing connections must not silently retain invalid privileges. |

## 4. Controlled outbound intelligence and update traffic

| ID | Mandatory requirement |
| --- | --- |
| `KS-NET-016` | The **manager's designated intelligence-update component** may contact public services only for administrator-approved, individually enabled purposes and providers. Examples include NVD CVE API, MITRE ATT&CK STIX/TAXII, CISA KEV, and verified update metadata; these names are candidates, not preauthorized endpoints. |
| `KS-NET-017` | External intelligence functions default **disabled until configured**. Users can enable individual providers, run an explicit sync, set frequency, review destination hosts, disable the feature, and use offline-imported data instead. |
| `KS-NET-018` | Provider requests must use approved HTTPS endpoints with TLS certificate/hostname validation. Versioning, response format validation, size/time/rate limits, safe cache handling, and verification of signatures/hashes when available are required. HTTP fallback and disabled TLS validation are prohibited. |
| `KS-NET-019` | DNS resolution for approved provider names may be permitted. The policy must validate both the hostname **and resolved/connected destination**; unexpected redirects, DNS rebinding, private/local/link-local targets, userinfo, alternate schemes, proxies, and IP literals may not bypass provider authorization. Explicitly authorized proxy use requires a separate reviewed policy. |
| `KS-NET-020` | Log records, filenames, network events, imported feed content, AI output, incident text, and third-party URLs must never cause arbitrary fetches. No automatic browsing of URLs extracted from telemetry, no SSRF, no unsanctioned threat enrichment endpoint. |
| `KS-NET-021` | No outbound upload of raw logs, flow records, hostnames, asset inventory, credentials, packet payloads, incident evidence, or AI prompts to public providers by default. CVE/indicator-specific lookups can disclose query terms and must have an explicit privacy explanation and administrative control. Prefer downloading public feeds when practical. |
| `KS-NET-022` | Manager-to-provider communication is separate from agent-to-manager transport. Agents, collectors, and isolated AI inference do not receive general Internet access or inherit the manager's intelligence permissions. |
| `KS-NET-023` | Feed syncing and update checks are nonessential to core collection, storage, detection, and incident operations. Outages, disabled feeds, or stale content must be visible to operators without blocking local monitoring. Stale data must not be presented as freshly verified. |
| `KS-NET-024` | Downloaded content must be treated as untrusted, even over TLS. Feed provenance, version, retrieval time, licensing, validation result, and safe error handling must be retained. No downloaded code or package is automatically executed or installed. |
| `KS-NET-025` | All permitted external transactions must generate privacy-preserving audit records with provider identity, purpose, success/failure, and timestamp, without recording secret tokens or unnecessary sensitive query details. |

Initial reference providers for later implementation include the [NVD APIs](https://nvd.nist.gov/developers),
[MITRE ATT&CK STIX/TAXII data](https://attack.mitre.org/resources/attack-data-and-tools/),
and [CISA's KEV catalog](https://github.com/cisagov/kev-data).
Provider APIs, formats, rate limits, licensing terms, and URLs may evolve; their
implementation must be versioned and reviewed in a separate engineering issue.

## 5. Configuration, enforcement, and change management

| ID | Mandatory requirement |
| --- | --- |
| `KS-NET-026` | Store approved monitoring assets/scopes, agent endpoints, and external provider permissions as distinct typed, versioned policy sections. Authorization is purpose- and component-specific, not a generic `allow_internet` switch. |
| `KS-NET-027` | Administrator changes to monitoring scope, outbound providers, agents, or policy exceptions require authorization, audit logging, validation, and safe rollback; remote events or AI results cannot expand the policy. |
| `KS-NET-028` | Enforce restrictions both at the application layer and through appropriate Linux process/service and host networking controls. A general Internet-capable host does not automatically authorize agent/collector Internet traffic. M3 must validate the effectiveness of actual deployed enforcement. |
| `KS-NET-029` | Unknown rules, invalid configurations, unavailable enforcement, failed policy activation, and partial updates must deny the *affected operation* rather than silently allowing it. Updates must not flush unrelated host firewall rules or transiently widen access. |
| `KS-NET-030` | Publish meaningful status and diagnostics for denied access, disabled feeds, invalid sources, sync failures, and policy changes. Do not disclose secrets or overstate enforcement success. |

### Illustrative policy intent (not a serializable configuration)

```yaml
monitoring:
  approved_local_segments: ["192.168.50.0/24"] # passive scope authorizes observed local devices
  approved_sensor_sources: ["gateway-A"] # actual source protocol decided later
  optional_enrolled_agents: []
  additional_local_routed_segments: [] # explicit per-segment approval only
agent_transport:
  allowed_manager_id: "manager-A"
  allow_public_internet_destination: false
intelligence_egress:
  enabled: false  # default; may be enabled by local administrator
  providers: [] # e.g. specifically approved NVD/MITRE/CISA sources
ai_inference:
  internet_access: false
```

This example is deliberately not executable and does not define a finished
configuration schema, ports, service user, or nftables implementation.

## 6. Scope limitations and unresolved implementation details

This policy can constrain KnetSentry processes within the supported threat
model. It cannot prove that a compromised host, local router, kernel, privileged
administrator, third-party sensor, or approved feed provider never forwards
information or provides false records. Firewall rule effects on other local
software require careful installation and rollback design.

M0.3 models malicious telemetry/feed content, DNS rebinding, supply-chain
injection, and credential compromise. M0.4 documents [process/API boundaries](../architecture/SYSTEM_ARCHITECTURE.md)
and [interface contracts](../architecture/INTERFACE_CONTRACTS.md);
implementation and enforcement are future work.
M3 will implement scoped transport and egress enforcement; M5 must add the
**minimal independently usable agentless sensor/gateway telemetry foundation**
so the first functional SIEM is not agent-dependent; M9 will expand network
telemetry and asset intelligence. Feed-connector implementation requires a
dedicated future issue; defining permission in M0.2 does **not** imply a
working CVE or ATT&CK sync client already exists.

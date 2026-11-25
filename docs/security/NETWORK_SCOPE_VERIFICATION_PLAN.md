<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Network Scope Verification Plan

**Status:** M0.2 specification retained. M3.1–M3.8 qualify subsets of the
policy, topology and isolated firewall requirements; operational monitoring,
authenticated transport and external provider tests remain future work. See
[project status](../PROJECT_STATUS.md) and [adversarial tests](../development/NETWORK_ADVERSARIAL_M37.md).
**Primary contract:** [NETWORK_SCOPE_REQUIREMENTS.md](NETWORK_SCOPE_REQUIREMENTS.md).
**Threat expansion:** [THREAT_MODEL.md](THREAT_MODEL.md) and
[THREAT_VERIFICATION_MATRIX.md](THREAT_VERIFICATION_MATRIX.md).

## 1. Methodology and evidence

Use deterministic unit tests for policy decisions, integration tests with
isolated Linux network namespaces, and end-to-end tests against supported
Ubuntu 26.04 nftables/systemd configurations. Do **not** send probes to public
Internet systems during CI: use local mock HTTPS services, fake DNS, and
controlled virtual networks. No test should alter the developer's ordinary
network or flush existing firewall policy. Record policy version, packet trace
where appropriate, test outcome, and exercised requirement IDs.

An authenticated flow, an **agentless observation of a LAN device without
endpoint software**, and a manager-to-public-feed fetch are separate categories;
tests must not conflate them. Validate real/representative router exports and
SPAN/tap interfaces in an authorized test environment; use synthetic fixtures
when required hardware is unavailable and report that limitation.

## 2. Monitoring authorization tests

| Test | Scenario and expected outcome | Requirements | Stage |
| --- | --- | --- | --- |
| `MON-01` | Agent on approved LAN host is enrolled and its selected source events are accepted. | 001,002,006 | M4–M6 |
| `MON-02` | An unknown local device on an **approved passive monitoring segment** may be inventoried and alerted on without a local agent or individual approval; it is denied elevated enrollment/management until separately authorized. | 001,002,032,038 | M5/M9 |
| `MON-03` | Authorized host → external Internet endpoint yields an allowed **observed** flow from its own telemetry. No generated probe is sent to the external endpoint. | 003,004,005 | M9 |
| `MON-04` | External endpoint → authorized LAN host yields a permitted observed inbound flow, with source/provenance. | 004,006 | M9 |
| `MON-05` | A random unrelated Internet address in a log is not auto-enrolled, scanned, DNS-looked-up, or fetched. | 002,004,020 | M3/M9 |
| `MON-06` | IPv4 private/public and IPv6 ULA/global/link-local addresses on approved local hosts are evaluated by attachment, identity, and scope, not simplistic address class. | 007,013 | M3/M9 |
| `MON-07` | Unauthorized passive capture interface and unauthorized network-device syslog source are rejected. | 003,005,006 | M9 |

## 2A. Agentless IoT visibility and security-alert tests

| Test | Scenario and expected outcome | Requirements | Stage |
| --- | --- | --- | --- |
| `MON-08` | A simulated printer or doorbell without an installed agent produces authorized gateway/flow telemetry. The manager ingests source-attributed events and the SIEM generates a supported network alert. | 031,033,037 | M5/M7 |
| `MON-09` | An approved segment observes a newly seen local address/MAC via available passive DHCP/flow data. Inventory and a new-device alert are created without automatically enrolling or trusting the device. | 001,032,038 | M5/M9 |
| `MON-10` | A sensor connected to an ordinary non-mirrored switch port is *not* credited with seeing unrelated unicast traffic. Coverage is incomplete rather than silently reported healthy. | 034,040 | M5/M8/M9 |
| `MON-11` | Mirrored traffic, permitted gateway flows, or authorized AP exports provide available IoT activity; missing traffic due to WLAN isolation, mirrored-port oversubscription, or asymmetric routing is indicated where measurable. | 033,034,040 | M5/M9 |
| `MON-12` | HTTPS/QUIC-like encrypted IoT flows provide permitted observable metadata but no false claim of decrypting payloads. | 005,035 | M5/M9 |
| `MON-13` | DHCP lease rollover, IPv6 privacy addresses, MAC spoofing/randomization, and NAT ambiguities do not silently merge unrelated assets. | 006,036,042 | M9 |
| `MON-14` | Flow anomaly tests produce positive and negative results with source evidence and confidence; malicious third-party event content cannot expand monitoring scope. | 006,037,027 | M7/M9 |
| `MON-15` | Raw packet capture and content retention are disabled by default; packet parsing is bounded; unauthorized capture interfaces are rejected. | 003,041 | M5/M13 |
| `MON-16` | Active local probing does not occur during passive monitoring; a hypothetical enabled scoped discovery operation is isolated from arbitrary WAN requests and must be separately approved. | 003,035,039 | M3/M9 |
| `MON-17` | An asset with only OUI or IP evidence cannot be marked as having a confirmed product model, firmware version, or applicable CVE. | 036,042 | M9/M10 |

## 3. Agent/control-plane network tests

| Test | Scenario and expected outcome | Requirements | Stage |
| --- | --- | --- | --- |
| `CTL-01` | Approved on-link agent can authenticate and connect to manager; unapproved peer cannot. | 008,009,011 | M3/M4 |
| `CTL-02` | Administrator-approved locally routed VLAN is permitted only through approved gateway/interface and explicit scope rules; unrelated route stays denied. | 009,010,015 | M3 |
| `CTL-03` | Default route to unrelated public host cannot carry agent transport, even if the host is listed in malformed configuration. | 008,010,014 | M3 |
| `CTL-04` | Wrong certificate, revoked agent, changed identity, or mismatched target is rejected. | 011,014 | M4 |
| `CTL-05` | IPv4-mapped IPv6, link-local scope, dual-stack, and unknown families cannot bypass authorization. | 013,014 | M3 |
| `CTL-06` | Route replacement, interface renumbering, VPN addition, or enforcement failure stops the affected transport until revalidated. | 010,014,015,028,029 | M3 |
| `CTL-07` | Local desktop IPC cannot be reached from remote network; unauthorized local peer is rejected. | 012 | M2 |

## 4. External intelligence egress and privacy tests

| Test | Scenario and expected outcome | Requirements | Stage |
| --- | --- | --- | --- |
| `INT-01` | With feeds disabled, no provider DNS or HTTPS connections occur. Core monitoring and local detections continue. | 016,017,023 | Egress/feed integration |
| `INT-02` | After approval, only the chosen provider and purpose can be reached by the designated service. | 016,017,022,026 | Egress/feed integration |
| `INT-03` | HTTPS hostname mismatch, expired certificate, HTTP downgrade, or unapproved redirect is denied. | 018,019 | Egress/feed integration |
| `INT-04` | DNS rebinding, CNAME/redirect to internal addresses, IP literal, link-local metadata URL, and unapproved proxy cannot circumvent provider allowlist. | 019,020 | Egress/feed integration |
| `INT-05` | Malicious URL in a journal event, CSV feed field, incident note, or AI response never initiates a request. | 020,022 | Egress/feed integration |
| `INT-06` | Outbound provider requests do not include raw logs, host inventory, packet payloads, keys, or incidents; on-demand CVE/indicator query disclosure is explicitly represented. | 021,025 | Egress/feed integration |
| `INT-07` | Oversized, malformed, misleading, or unsupported feed data is rejected/quarantined without loss of local monitoring. | 018,023,024 | Feed integration |
| `INT-08` | Offline mode, provider outage, or stale cached data is reported accurately; the last known verified feed version is preserved. | 023,024,030 | Feed integration |
| `INT-09` | Agents and AI workers cannot access the public feed egress path even when manager sync is enabled. | 022,028 | Egress/feed integration |
| `INT-10` | Configuration rollback and denied provider changes never temporarily widen network access or disable unrelated host firewall policy. | 027,028,029 | M3/egress |

## 5. Operational and security review gates

| Gate | Expected evidence | Requirements |
| --- | --- | --- |
| `OPS-01` | Config schema validation, administrator approval, auditable changes and denials | 025–027,030 |
| `OPS-02` | Application checks combined with effective systemd/nftables enforcement on supported OS | 014,015,028,029 |
| `OPS-03` | No false assertion of end-to-end visibility; demonstrate encrypted traffic, sensor-position gaps, and missing-source limitations | 005,006,034,035,040 |
| `OPS-04` | Confirm service/network policies remain effective across restart, route changes and error recovery | 014,015,028–030 |

## 6. Issue traceability and release status

- **M0.2:** Requirements, matrix and prospective tests only.
- **M0.3:** Threat model including malicious feed content, SSRF, DNS rebinding,
  compromised agents, compromised manager, and adversarial local hosts.
- **M0.4:** Architecture and component ownership of monitoring, control-plane
  transport, and outbound intelligence client.
- **M3.1–M3.8:** Monitoring/transport scope and Linux enforcement, expanded to
  support separately authorized intelligence egress.
- **M4–M6:** Agent enrollment and optional host telemetry; in M5, ship a
  *minimal agentless passive/gateway telemetry source* independent of agents.
- **M7:** At least one evidence-backed network security alert from an
  agentless source to establish agentless end-to-end SIEM functionality.
- **M7.9/M10:** MITRE ATT&CK mappings, with updates/sync requiring a separate
  dedicated feed-implementation issue to be created or added to the roadmap.
- **M9:** Expand gateway/AP/network-device adapters, passive connection
  metadata, agentless asset identification, IoT anomaly detections, and
  coverage visualization. External conversation peers are not monitored hosts.
- **M12:** Isolated local AI without general network access.
- **M13/M15:** Adversarial requalification and release sign-off.

Do not mark unimplemented tests as passed. A future exception must link to an
approved policy change and corresponding regression test.

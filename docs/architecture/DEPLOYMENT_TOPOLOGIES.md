<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Deployment and Observability Profiles

**Issue:** M0.4. **Status:** design examples, not implemented installers or
certified coverage. See [system architecture](SYSTEM_ARCHITECTURE.md),
[components](COMPONENT_CATALOG.md),
[interfaces](INTERFACE_CONTRACTS.md), and
[M0.2 network requirements](../security/NETWORK_SCOPE_REQUIREMENTS.md).

## Profile D-01 — Single Ubuntu workstation and approved gateway export

```text
  printer / camera / smart doorbell --Wi-Fi/Ethernet--> LAN router
                                   [approved DHCP/DNS/flow/syslog export]
                                                     |
                                      authorized local export transport
                                                     v
                      Ubuntu 26.04 AMD64 workstation
                      +-------------------------------------+
                      | gateway adapter -> ingest -> store |
                      | manager -> rules -> cases          |
                      | Qt/Kirigami desktop (non-root)     |
                      +-------------------------------------+
```

- **Agent installation on IoT devices:** none. Device enrollment is not a
  prerequisite to passively observing newly seen devices on approved scopes.
- **Required telemetry precondition:** the gateway must actually export
  useful supported records. A home router that lacks export functionality
  does **not** grant hypothetical visibility to KnetSentry.
- **Coverage:** reflect exactly which destinations/flows/logs are exported,
  and whether NAT, VLANs, encrypted traffic, vendor clouds and Wi-Fi isolation
  limit conclusions. Unverified sender identity stays unverified.
- **Network egress:** no external provider access unless the operator opts in.
  A provider request does not constitute observation or scanning of an
  Internet host appearing in IoT traffic.

## Profile D-02 — Dedicated passive mirror/tap sensor and manager

```text
LAN switch / monitored port -> mirror/tap -> Ubuntu sensor NIC
                                              |
                         capture broker (minimal capability) -> parser worker
                                              |
                     [local IPC if colocated / sensor-specific mTLS if remote]
                                              v
                          Ubuntu manager -> database/rules -> Qt desktop
```

- Passive observation is restricted to approved interface/scope; raw packet
  retention is **off unless separately enabled and reviewed**. A sensor may
  infer flow/protocol metadata without reading TLS/QUIC application plaintext.
- Local colocated sensor uses guarded IPC; remote Ubuntu sensor uses a
  sensor-specific enrollment/authorization profile over an approved local
  transport, not an assumed unrestricted agent credential.
- No traffic tap or mirroring means no guarantee of seeing unicast flows
  between other switch ports. Overloaded mirror/tap produces observable loss,
  not a fictitious healthy monitoring status.
- Capture broker and packet parser are separate processes; broker must not
  parse arbitrary network protocol fields with its capture privileges.

## Profile D-03 — Agent-enriched authorized LAN

```text
optional Ubuntu endpoint agent  ---> authenticated LAN receiver --> manager
approved gateway/passive sensor --> approved ingestion boundary --> manager
                                                                 |
                                                       normalized evidence
                                                                 v
                                                  detections/cases/Qt GUI
```

- Host logs/processes/file integrity can enrich passive IoT network evidence.
  No host-agent enrollment is required for baseline network alerts.
- Agent identity authenticates the sender and enrollment but cannot establish
  the truth of data produced by a compromised endpoint.
- A remote public server observed as a flow peer is never automatically
  enrolled, monitored as a local asset, or contacted for investigation.

## Profile D-04 — Multiple approved local VLANs or routed LAN segments

The administrator separately approves participating observation domains and
interfaces; routes, VLAN attachment, access-control permissions, and sensor
placement are reviewed and tested. `KS-NET-007` permits approved local public,
ULA and RFC 1918 addresses when validated; addresses alone prove neither
locality nor authority. VPNs, public Internet peers, arbitrary default-route
reachability, and unknown remote subnets are **not automatically included**.

The future `C-02` policy engine authorizes each intended data and control
path, while `C-21` host policy independently verifies effective restrictions.
If network state changes invalidate a scope, the affected operation fails
closed while relevant observation/coverage status is marked degraded.

## Capacity assumptions across deployment profiles

The [M0.5 workload profiles](../development/WORKLOAD_PROFILES.md) require an
agentless reporting source independently of optional endpoint agents.
[Performance requirements](../development/PERFORMANCE_REQUIREMENTS.md)
measure raw capture PPS separately from normalized events/s. A workstation
running a gateway export adapter may have no direct access to mirrored
packets; a dedicated mirror sensor may observe more packets but produce fewer
normalized records. Neither is evidence of complete network visibility.

Storage capacity and seven-day retention depend on actual event sizes, indexes,
spools and headroom; see the
[resource model](../development/RESOURCE_CAPACITY_MODEL.md). These provisional
capacity envelopes are **not hardware minimums or achieved throughput claims**.

## Shared operating assumptions and prohibitions

1. **Manager, desktop, privileged capture and feed egress are distinct
   authorities.** Root GUI, all-in-one privileged packet parser, or
   Internet-enabled AI worker are prohibited baseline designs.
2. Supported sensors and managers initially run on Ubuntu 26.04 AMD64;
   third-party devices contribute supported telemetry without running KnetSentry.
3. No generic Internet peer probing, blanket network scanning, ARP spoofing,
   unauthorized interception, TLS MITM or silent packet-payload retention.
4. The operator can view observed/partial/unavailable coverage and tentative
   identity; no claim of "100% of devices protected" follows from an inventory.
5. The service remains operational without cloud accounts, Internet access,
   endpoint agents, or AI models where a valid local agentless telemetry source
   exists.
6. Installing a capture sensor on a machine does not itself authorize or
   provision a switch mirror, tap, AP/controller export or gateway integration.

## Acceptance examples for later milestones

| Scenario | Required eventual observation | Principal owner |
| --- | --- | --- |
| IoT printer contacts unusual external address in approved gateway flow feed | Source-tagged flow metadata, tentative asset, alert with evidence; no agent installed on printer | M5.10/M7.10 |
| Normal switched port sees no doorbell traffic | Partial/unavailable coverage with explanation, never absence-of-threat conclusion | M5.10/M9.6 |
| Forged source export with unverified sender | Low-trust record marking or rejection according to policy; no administrative action | M5.10/M6.1 |
| Approved MITRE feed sync enabled | Outbound request only through isolated approved provider client, audited and validated | M3.9/M10.9 |
| Compromised endpoint with valid agent key | Transport principal identified; event claims still untrusted; manager roles not inherited | M4/M6/M13 |
| Operator approves tightly scoped response | Independently authorized and audited action; disabled by default | M11.5 |

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry — Network Communication and Observation Matrix

**Status:** M0.2 planned traffic roles, not implemented endpoints.
**Normative requirements:** [NETWORK_SCOPE_REQUIREMENTS.md](../security/NETWORK_SCOPE_REQUIREMENTS.md).

| Activity | Source and destination | Authorized? | Trust boundary / restriction | Future stage |
| --- | --- | --- | --- | --- |
| Agent telemetry | Approved enrolled LAN endpoint → approved manager | Yes | Explicit approved LAN path, authenticated peer, encrypted transport | M4–M6 |
| Manager responses | Manager → agent on approved session | Yes | Authenticated session state and policy; no generic remote shell | M4 |
| Qt desktop/CLI control | Local GUI/CLI → manager Unix-domain socket | Yes | Local peer authentication and authorization; no exposed public listener | M2 |
| Local host collection | Authorized OS records → local endpoint agent | Yes | Collector privileges and data-minimization rules | M5 |
| Agentless gateway/flow export | Approved gateway/router/firewall → configured ingest service | **Core, source-dependent** | Authorized local monitoring scope; source capability and provenance checks; no device agent needed | M5 foundation / M9 expansion |
| Agentless passive capture | Approved mirror/tap/sensor interface → local network flow metadata | **Core, when traffic is supplied** | Bounded least-privilege capture of approved segment; packet availability cannot be presumed | M5 foundation / M9 expansion |
| Device and network discovery metadata | Authorized DHCP/DNS/AP/controller source → local asset inventory | Core, when available | Device identity tentative; observed unknown LAN devices need no per-device enrollment | M5/M9 |
| LAN device syslog | Approved local network device → configured collector | Supported integration | Restricted sender/source; unauthenticated syslog may be spoofed; no installed agent required | M9 |
| Workstation → public server | Authorized *local* host's observed outbound flow | **Observe** | May record external peer; KnetSentry does not contact it to verify | M5/M9 |
| Public server → workstation | Authorized *local* host's observed inbound flow | **Observe** | Remote sender is not enrolled/monitored asset | M5/M9 |
| NVD / vulnerability data | Dedicated manager feed component → approved public API | Opt-in | HTTPS, approved provider, query privacy, bounded/validated responses | Dedicated feed issue |
| MITRE ATT&CK data | Dedicated manager feed component → approved STIX/TAXII origin | Opt-in | Provenance/version validation, audit, no telemetry upload | Dedicated feed issue |
| CISA KEV/approved feeds | Dedicated manager feed component → approved source | Opt-in | TLS, source allowlist, payload validation, disabled by default | Dedicated feed issue |
| Software update metadata | Approved update checker → vetted metadata source | Opt-in | Validate signatures/checksums when available; no unattended code execution | Release engineering |
| Local AI inference | Manager → isolated local inference process | Yes | Restricted IPC, no Internet for inference worker | M12 |
| Unrequested external host probe | KnetSentry → arbitrary Internet address | **No** | No scanning, active discovery, or automatic follow-up to observed peer | All |
| Unapproved telemetry upload | KnetSentry → cloud service | **No** | Private logs, inventory, incidents, and packet data never uploaded by default | All |
| External SaaS or LLM | KnetSentry → third-party cloud inference | **No** (initial release) | Not a prerequisite; local AI is optional | M12 |

### Example: agentless printer/doorbell monitoring

A printer or doorbell inside an approved LAN segment contacts an external
service. A supported gateway export or mirrored traffic sensor **may** capture
connection metadata and report it to KnetSentry **without installing anything
on that device**. Depending on the telemetry source, the SIEM can identify
new destinations, repeated connection patterns, unexpected ports, or changes
in observed behavior. The sensor must report missing interfaces, unavailable
flows, packet drops, encrypted application data, and uncertain identity.
No automatic inbound probe of the remote Internet peer is authorized, and
one ordinary workstation port cannot be assumed to see the whole LAN.

### Example: optional agent-enriched endpoint monitoring

An enrolled Ubuntu endpoint `192.168.50.11` connects to a public HTTPS host.
The authorized local agent can observe connection metadata available to its
collector and forward it to the approved manager at `192.168.50.10`. The public
server's address appears in the event, **but the manager does not contact that
server** as a result of observing the event. Independently, if the administrator
has explicitly enabled NVD updates, the manager's restricted feed component
may contact an approved NVD API endpoint to download vulnerability information.
These are different authorization decisions and independently auditable flows.

A separately approved LAN VLAN may participate if local topology, transport,
firewall policy, and endpoint authorization have been validated. No general
permission to traverse arbitrary routed networks is implied.

### Deployment limitations

The specific transport protocol, ports, IPC path, certificate profile, source
binding, DNS strategy, firewall rules, and feed-client implementation are
*not yet defined or deployed*. M0.4/M3/M4 and the later feed integration issue
must make those decisions with test evidence.

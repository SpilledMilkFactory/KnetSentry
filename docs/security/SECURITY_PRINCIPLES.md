<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry — Foundational Security Principles

**Status:** M0.1 requirements baseline. These are intended controls, **not**
claims that KnetSentry already provides operational security protections.

## 1. Security goals and trust assumptions

KnetSentry should provide authorized local monitoring without exposing
telemetry, credentials, protected administration interfaces, or the underlying
system to unnecessary risk. The LAN is **not a trusted boundary**: local
systems may be compromised, records may be adversarially crafted, and
credentials may be stolen. Authenticated transport establishes an identity,
not proof that the sender's operating system is uncompromised.

M0.3 defines the [initial threat model](THREAT_MODEL.md),
[threat register](THREAT_REGISTER.md), and
[verification ownership](THREAT_VERIFICATION_MATRIX.md). Risk mitigation
remains planned, and residual risk is unassessed until controls are built and
verified. We will not claim to defeat a compromised kernel or every fully
privileged local attacker.

## 2. Foundational requirements

### Privilege separation and least authority

- The Qt desktop operates as an ordinary user; it does not require root.
- Manager, agents, privileged collectors, storage, and optional inference
  receive only the capabilities needed to perform their own duties.
- Service accounts, filesystem permissions, systemd hardening, capability
  restrictions, and authenticated IPC enforce independently reviewable
  boundaries.
- Authentication and permission failures must not silently elevate access.

### Explicit local-network scope

- The **monitoring boundary** is administrator-approved LAN segments and
  authorized sensors/gateway sources, including unknown IoT devices observed
  within that scope without installing endpoint agents. Per-device approval is
  not needed for passive observation inside the approved monitoring domain;
  agents and privileged management access still require explicit enrollment.
  Local devices' Internet peer metadata may be recorded when observable.
  No active scanning, probing, or enrollment of unrelated Internet hosts.
- Monitor **source coverage and gaps**. Passive sensors on ordinary switched
  or wireless ports are not assumed to see other devices' unicast traffic;
  access-point isolation, encryption, asymmetric routes, and dropped mirror
  packets must be surfaced as visibility limitations.
- Treat device identity, manufacturer, model, firmware, and corresponding CVE
  matches as evidence-dependent. DHCP/MAC/IP and vendor heuristics alone do not
  justify claiming a confirmed device identity or vulnerability.
- Agent-to-manager transport stays on approved, authenticated LAN paths;
  local presence or private addressing never substitutes for identity.
- A designated manager component may perform **opt-in HTTPS** synchronization
  with approved CVE, MITRE ATT&CK, CISA KEV, or other security-information
  sources, with provider allowlists, TLS validation, size limits, and auditing.
- Privacy protections prohibit automatic outbound transfer of host logs,
  evidence, inventories, packet contents, credentials, or incidents.
- IPv4/IPv6, interface/route changes, dual-stack handling, and scoped IPv6
  addresses must be evaluated; uncertainty fails closed for affected flows.
- Host-level network enforcement backs application-level permission checks.
- The [M0.2 network contract](NETWORK_SCOPE_REQUIREMENTS.md) and its
  [verification plan](NETWORK_SCOPE_VERIFICATION_PLAN.md) define auditable
  boundaries between authorized monitoring, agent transport, and optional
  external intelligence access.

### Cryptographic identities and transport

- Use maintained cryptographic libraries and standard protocols, not custom
  primitives or novel handshakes.
- Require explicit enrollment and mutually authenticated, encrypted agent
  transport, with certificate validation, rotation, expiration, revocation,
  and auditable authorization decisions.
- Protect private keys and tokens; never record secrets in diagnostics.
- Bound message sizes, retry behavior, and connection resource consumption.

### Input handling and evidence provenance

- Treat journals, logs, process arguments, filenames, network records,
  detection rules, IPC requests, agent messages, and AI inputs as untrusted.
- Validate lengths, types, encodings, paths, identifiers, timestamps, and
  nesting; isolate expensive parsing and avoid unbounded allocations.
- Retain available original evidence, source identities, acquisition times,
  and normalization metadata according to retention policy.
- Integrity metadata can detect some later changes; it cannot guarantee that
  untrusted-origin content was true or complete.
- Alert explanations require supporting evidence and must not confuse
  correlation with proven causality.

### Privacy, auditing, and retention

- Collect only approved sources and fields, with configurable exclusions,
  redaction, and storage limits.
- Apply consistent access controls across the GUI, CLI, local IPC, reports,
  configuration changes, and evidence exports.
- Audit administrative actions while protecting credentials, tokens, private
  keys, and sensitive telemetry from accidental log disclosure.
- Retention and deletion must behave predictably under available storage,
  privilege, or connectivity failures.

### Offline AI and model isolation

- AI remains optional and never blocks normal SIEM operation.
- Inference is restricted by process identity, filesystem, CPU/memory, and
  network policy; default design does not grant network access.
- Treat telemetry and retrieved records as **data**, not model instructions;
  tool restrictions and authorization must be independently enforced.
- Mark model output as generated, retain relevant provenance and model
  identity, and require appropriate human approval for response actions.
- Do not claim prompt-injection defenses are infallible.

### Secure code and supply chain

- Favor clear C++ ownership, RAII, bounded resources, robust error handling,
  carefully reviewed dependencies, and minimal privileged interfaces.
- Preserve third-party licensing, checksums, version provenance, and
  redistribution notices as components are introduced.
- Add strict warnings, automated tests, static analysis, sanitizers, fuzzing,
  and adversarial fixtures according to affected trust boundaries.
- Do not represent an unrun test or unreviewed control as security evidence.

## 2A. M0.4 process and authority separation

The [modular architecture](../architecture/SYSTEM_ARCHITECTURE.md) and
[interface design](../architecture/INTERFACE_CONTRACTS.md) establish planned
independent roles for privileged capture versus unprivileged packet parsing,
local GUI/CLI versus authorized management IPC, authenticated agent
transport versus source truth, restricted provider HTTPS egress versus
observed external peers, and offline AI versus deterministic detection.
The proposed component privileges and future verification owners are
recorded in the [component catalog](../architecture/COMPONENT_CATALOG.md)
and [architecture traceability](../architecture/ARCHITECTURE_TRACEABILITY.md).
These are design boundaries only; isolation effectiveness remains unverified.

## 3. Response safety

Detection is not authorization to intervene. Active response is disabled by
default, narrowly scoped, auditable, and requires explicit approval according
to the policy defined in its later milestone. AI recommendations cannot grant
privileges or authorize actions by themselves.

## 4. Required evidence for future security claims

| Requirement | Planned validation |
| --- | --- |
| LAN-scoped agentless monitoring | Approved sensor and network-scope tests, IoT traffic evidence without agents, external-peer flow observation, prohibited active external probing |
| Sensor visibility and attribution | Gateway/SPAN coverage and gap tests, encrypted-metadata limits, ambiguous device identity and spoofed DHCP/MAC handling |
| Restricted external intelligence egress | Provider allowlists, TLS/redirect/DNS tests, privacy and offline-mode checks |
| Agent transport boundaries | Route/scope tests, host enforcement, namespace-based adversarial checks |
| Trusted agent communication | Enrollment, mutual-authentication, credential lifecycle, rejection tests |
| Least-privilege services | systemd, filesystem, capabilities, and local IPC authorization tests |
| Safe processing | Parser tests, fuzzing, sanitizer checks, size and resource-limit tests |
| Traceable evidence | Provenance, integrity, retention, and report-consistency tests |
| Restricted optional AI | Isolation, malicious-input, denied-tool, and audit tests |

No release should be signed off while known findings classified as
release-blocking remain unresolved. Automated checks are necessary but cannot
prove that the system is vulnerability-free.

## 5. Follow-up issue ownership

- **M0.2–M0.4:** LAN policy and threat model documented in M0.2/M0.3;
  M0.4 documents the proposed separation of processes and logical APIs.
- **M0.6–M0.7:** Licensing/supply-chain controls and quality requirements.
- **M3–M4:** Network isolation, authenticated enrollment, secure transport.
- **M5–M11:** Privacy-aware collection, evidence, detections, incidents.
- **M12–M13:** Optional AI isolation and platform-wide adversarial review.

Security exceptions must be explicit, justified, and tested. Convenience is
not sufficient reason to bypass a defined security boundary.

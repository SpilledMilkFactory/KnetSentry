<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry — Product Vision

**Status:** M0.1 foundation requirements; proposed behavior, not an implemented
or certified security capability.  
**Tagline:** Local Network Security Intelligence  
**Release target:** Independent KnetSentry v1.0.0, Ubuntu 26.04 LTS AMD64.

## 1. Vision and problem

Security-relevant evidence from a home lab, small office, or research LAN is
often scattered across hosts, journals, audit facilities, and network devices.
KnetSentry aims to turn **authorized local telemetry** into a consistent,
searchable account of activity, actionable detections, and reproducible incident
investigations, without requiring cloud-hosted services or sending telemetry to
the Internet.

The central design goal is **verifiable local security intelligence**: the
system should explain what it observed, where an event originated, why a rule
fired, what remains uncertain, and how an analyst can inspect supporting data.
It is not intended to assert complete knowledge of every connected device.

## 2. Intended users

| User | Need | Intended workflow |
| --- | --- | --- |
| Home-lab administrator | Observe smart-home devices, printers, and managed hosts | Configure agentless sensor/gateway sources; optionally enroll agents |
| Small-network operator | Centralize locally available network and host evidence | Search events, inspect coverage, tune rules, manage retention |
| Security analyst or student | Investigate multi-host activity | Pivot across sources, build timelines, document findings |
| Detection engineer | Develop and validate defensible detections | Write rules, run positive/negative fixtures, inspect evidence |
| Researcher or contributor | Study secure C++ security-system design | Review threat models, tests, and documented architecture |

Administrators are responsible for obtaining authorization to monitor the
systems, accounts, and network segments they configure. The product must offer
configuration and privacy controls that support this responsibility.

## 3. Core product goals

1. **LAN-focused monitoring with controlled intelligence egress:** Monitor only
   approved local assets and authorized network sources, including available
   Internet-bound/inbound activity involving those assets. Restrict agent
   transport to approved LAN paths; allow opt-in manager HTTPS access to vetted
   CVE, MITRE ATT&CK, and other public security-information providers.
2. **Strong system boundaries:** Separate the unprivileged Qt desktop from the
   manager, agent, narrow privileged collectors, storage, and optional AI.
3. **Agentless-first, trustworthy collection:** Observe local devices—including
   printers, cameras, doorbells, and IoT appliances—without installing software
   on them. Approve the **network/sensor monitoring scope**, not every passively
   observed device individually; identify devices through available network
   records with confidence limits. Enroll and authenticate **optional** host
   agents for deeper telemetry; protect sensor transport and evidence provenance.
4. **Interoperable event processing:** Validate, normalize, store, index, query,
   and retain telemetry using versioned formats; OCSF is the planned schema
   reference, subject to a pinned implementation profile.
5. **Explainable detection:** Keep deterministic, reproducible rule-based
   detection functional without AI. Support traceable alerts, correlation,
   analyst review, and carefully scoped MITRE ATT&CK mappings.
6. **Complete investigations:** Offer asset views, search, alert lifecycles,
   incident records, evidence integrity metadata, and exportable reports.
7. **Quality desktop experience:** Provide a polished Qt 6/Qt Quick/Kirigami
   interface usable under GNOME and KDE Plasma, with keyboard navigation,
   readable visualizations, and reduced-motion support.
8. **Defensible engineering:** Require explicit threat modeling, least
   privilege, input validation, fuzzing, repeatable tests, static analysis,
   dependency review, and security evidence for release claims.
9. **Privacy-preserving optional AI:** Allow isolated, offline, auditable AI
   assistance. Untrusted telemetry may not issue instructions to the model's
   host or authorize privileged operations.
10. **Open-source maintainability:** Publish reproducible development steps,
    understandable documentation, transparent limitations, and an eventual
    pathway to KDE community review without assuming approval.

## 4. Intended end-to-end experience

For an authorized home/small-office LAN, an Ubuntu workstation runs the
manager and desktop and receives mirrored traffic or supported gateway
telemetry. A printer or smart-home device **without an installed agent** makes
an observable connection to a new external destination. KnetSentry is expected
to associate the connection with the correct local asset when evidence permits,
normalize and persist it, flag a reproducible suspicious-behavior scenario,
show what source observed it and which traffic remains unseen, and support
investigation and reporting. An enrolled Ubuntu endpoint may contribute deeper
host telemetry, but is not required for this **agentless** scenario. An optional
local AI summary may assist but is not required or authoritative.

This is a **future v1.0.0 acceptance scenario**, not a claim that it works today.

## 5. Non-goals for the initial release

- Cloud-hosted management, externally hosted AI, unsolicited telemetry upload,
  automatic Internet browsing, external analytics, or remote SaaS dependency.
  Approved public vulnerability/ATT&CK feeds and update metadata are allowed
  as separately authorized, privacy-conscious outbound requests.
- Unapproved **active** probing, intrusive scanning, or device enrollment.
  **Passive identification and inventory of previously unknown devices is in
  scope within an explicitly approved local network/sensor scope**, without
  per-device agent enrollment. Any future active local discovery must be
  separately opted in, rate-limited, and scope-restricted.
- Guaranteeing observation of traffic that a configured gateway, sensor, or
  mirror cannot actually see; decrypting private communications without
  authorized key access; or claiming reliable firmware/CVE attribution solely
  from a MAC address or manufacturer guess.
- Active monitoring, scanning, probing, or enrolling unrelated Internet hosts.
  Observing external conversation peers in authorized LAN traffic is in scope;
  locally routed VLANs require explicit approval and policy validation, while
  unapproved VPNs, tunnels, and network interfaces remain excluded.
- Windows or non-Ubuntu endpoint agents, ARM targets, or broadly supported
  distribution packages in the initial v1.0.0 release.
- Enterprise multi-region clustering, infinite retention, lossless operation
  through arbitrary failures, or an unqualified events-per-second claim.
- Unrestricted automated response, unattended endpoint isolation, or
  unreviewed AI-directed administrative actions.
- Formal KDE project affiliation or KDE infrastructure migration before the
  separate post-v1.0 KDE-adoption process.
- Claims that a passing test suite proves the absence of vulnerabilities or
  that event correlation alone establishes causation.

## 6. Release-level success criteria

The initial release is successful only when evidence shows that:

- An authorized Ubuntu 26.04 AMD64 deployment can install and operate a
  manager, desktop, and supported agent configuration.
- An agentless sensor or gateway source can provide security-relevant flows
  for a local printer/IoT device without installing software on that device;
  the operator can see its known coverage limits.
- Optional enrolled agents can deliver authentic host telemetry; unauthorized
  enrollment and out-of-scope agent transport are rejected.
- Stored events are searchable and source-attributed; deterministic alerts
  link to supporting evidence; an incident can be investigated and exported.
- The Qt desktop remains usable under GNOME and KDE Plasma and does not require
  elevated privileges to display or investigate data.
- Optional offline AI can be disabled without breaking the security workflow.
- Required security, reliability, documentation, redistribution, and release
  checks pass for the source revision being published.

Quantitative thresholds for throughput, detection latency, storage, recovery,
and UI responsiveness are **not yet approved**; M0.5 will define measurable
criteria and M14 will validate them.

## 7. Governance and decisions still to be made

- **M0.2 (defined):** The [network-security contract](docs/security/NETWORK_SCOPE_REQUIREMENTS.md)
  separates authorized LAN observation, local authenticated agent transport,
  and optional manager egress to approved external security-intelligence feeds.
  IPv4/IPv6, routed LAN segments, identity, privacy, and fail-closed policy
  must be addressed in subsequent implementation and tests.
- **M0.3 (defined):** The [initial threat model](docs/security/THREAT_MODEL.md),
  [risk register](docs/security/THREAT_REGISTER.md), and
  [future verification matrix](docs/security/THREAT_VERIFICATION_MATRIX.md)
  identify adversaries, trust boundaries, abuse cases, proposed controls, and
  accountable future tests. No mitigations are deployed and residual risks
  are **not yet assessed or accepted**.
- **M0.4:** Component boundaries, APIs, and storage/transport design.
- **M0.5:** Resource budgets and benchmark thresholds.
- **M0.6:** Final component-level licensing, third-party obligations, and
  SPDX/REUSE implementation. The existing repository license is currently MIT.
- **M0.7–M0.8:** Quality gates, governance, and disclosure procedures.

The roadmap is a plan. Features are not represented as implemented until their
own milestones pass acceptance. Security decisions are recorded and revised
explicitly, rather than silently broadened through feature work.

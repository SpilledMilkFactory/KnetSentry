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
| Home-lab administrator | Understand security activity on owned hosts | Enroll agents, review host health and alerts |
| Small-network operator | Centralize locally available evidence | Search events, tune rules, manage retention |
| Security analyst or student | Investigate multi-host activity | Pivot across sources, build timelines, document findings |
| Detection engineer | Develop and validate defensible detections | Write rules, run positive/negative fixtures, inspect evidence |
| Researcher or contributor | Study secure C++ security-system design | Review threat models, tests, and documented architecture |

Administrators are responsible for obtaining authorization to monitor the
systems, accounts, and network segments they configure. The product must offer
configuration and privacy controls that support this responsibility.

## 3. Core product goals

1. **Local-only operations:** KnetSentry components do not initiate Internet
   connections; network activity is restricted to approved LAN destinations,
   interfaces, routes, and enrolled peers. Both IPv4 and IPv6 are in scope.
2. **Strong system boundaries:** Separate the unprivileged Qt desktop from the
   manager, agent, narrow privileged collectors, storage, and optional AI.
3. **Trustworthy collection:** Enroll devices explicitly; authenticate agents;
   encrypt transport; preserve event provenance and record source limitations.
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

For an authorized three-machine LAN, one Ubuntu workstation runs the manager
and Qt desktop while two enrolled Ubuntu endpoints run agents. A controlled,
authorized SSH authentication test generates events. KnetSentry is expected to
collect, authenticate, normalize, and persist selected records; a deterministic
rule detects the documented pattern; an analyst can view evidence, create an
incident, annotate findings, and export a report. An optional local AI summary
may assist but is not required or authoritative.

This is a **future v1.0.0 acceptance scenario**, not a claim that it works today.

## 5. Non-goals for the initial release

- Cloud-hosted management, externally hosted AI, third-party telemetry upload,
  Internet-based update checks, external analytics, or remote SaaS dependency.
- Automatic discovery, probing, scanning, or enrollment of arbitrary LAN
  devices without an explicit administrative authorization and source policy.
- Guaranteeing visibility into devices that do not provide authorized telemetry,
  or decrypting communications that KnetSentry is not entitled to access.
- Monitoring the public Internet or network segments outside configured LAN
  scope; VPN and routed subnets are excluded unless explicitly supported and
  approved by the future network-scope policy.
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
- An enrolled agent can deliver authentic telemetry through the approved
  network scope; unauthorized enrollment and out-of-scope traffic are rejected
  under a documented threat model.
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

- **M0.2:** Precise interface, route, subnet, IPv6, VLAN, and egress policy.
- **M0.3:** Formal adversary model and accepted residual risks.
- **M0.4:** Component boundaries, APIs, and storage/transport design.
- **M0.5:** Resource budgets and benchmark thresholds.
- **M0.6:** Final component-level licensing, third-party obligations, and
  SPDX/REUSE implementation. The existing repository license is currently MIT.
- **M0.7–M0.8:** Quality gates, governance, and disclosure procedures.

The roadmap is a plan. Features are not represented as implemented until their
own milestones pass acceptance. Security decisions are recorded and revised
explicitly, rather than silently broadened through feature work.

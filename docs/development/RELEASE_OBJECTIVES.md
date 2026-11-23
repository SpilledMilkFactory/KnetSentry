<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry — Release Objectives and Acceptance Strategy

**Status:** M0.1 planning baseline refined by M0.2 monitoring and network
security requirements. Milestone success requires future implementation and
repeatable verification evidence.

## 1. Release target

The first stable target is **KnetSentry v1.0.0** for **Ubuntu 26.04 LTS
AMD64/x86-64**. Planned deliverables include a Qt 6/Kirigami desktop, a
manager service, an agentless network-sensor capability, and an **optional**
endpoint agent, packaged with appropriate dependencies.
The desktop must operate under GNOME and KDE Plasma on the supported OS.

M0.1 ships **documentation only**. It does not claim that software, tests,
security controls, or release artifacts already exist.

## 2. Roadmap stages

| Stage | Milestones | Target outcome |
| --- | --- | --- |
| Foundation | M0–M3 | Documented requirements, Qt shell, manager, tested network boundary |
| Functional SIEM | M4–M7 | Agentless sensor/gateway events, optional enrolled agents, storage, deterministic alerts |
| Advanced security operations | M8–M12 | SOC dashboards, assets, correlation, incidents, optional offline AI |
| Production qualification | M13–M15 | Security review, long-run reliability, Ubuntu packages, v1.0.0 release |
| KDE community adoption | M16 | Separate post-v1.0 Incubation/Review effort, subject to KDE approval |

## 3. Functional release criteria

1. Install and operate the manager and Qt desktop on Ubuntu 26.04 AMD64;
   validate both supported desktop environments.
2. Approve local monitoring network/sensor scopes and ingest observable
   network telemetry from a device **without software installed on that
   device**. Passive identification of unknown devices within approved scope
   is supported; optional agent enrollment remains explicitly authorized.
3. Collect selected real network/gateway telemetry, and optional host telemetry,
   using secured sensor transport where applicable, with source attribution,
   device identity confidence, coverage limitations, and fault reporting.
4. Validate, normalize, attribute, retain, search, and inspect events.
5. Run reproducible deterministic detection rules and generate alerts linked
   to supporting records; preserve source and confidence limitations.
6. Correlate supported multi-host events without inventing data from devices
   that do not provide authorized telemetry.
7. Create an incident, attach evidence, document an investigation, and export
   an appropriately authorized and accurate report.
8. Repeat the core workflow **with AI disabled**; if AI is enabled, validate
   local execution, process isolation, and visible AI attribution.
9. Verify installation, upgrade, and removal behaviors on clean supported
   Ubuntu systems using the exact intended release packages.

The **required agentless integration demonstration** is a smart-home device or
printer within an approved local network communicating with a simulated or
legitimate external destination, with the traffic delivered by a configured
sensor or gateway export and an evidence-backed behavior alert produced **with
no software installed on the monitored device**. The GUI must show which
networks/devices are covered and which are not. A separate optional-agent
scenario exercises a controlled SSH authentication sequence. Neither test
probes unrelated remote systems. Optional external-intelligence feeds must
be separately authorized and are not required for core SIEM operation.

## 4. Security release criteria

- Explicit monitoring-source boundaries, authenticated LAN transport, and
  optional provider-restricted HTTPS intelligence egress; IPv4/IPv6 and
  host-level enforcement must fail closed for the affected operation.
- Local monitoring must function without Internet connectivity and without
  transmitting private evidence to external providers by default.
- Tested enrollment, credentials, mutual authentication, authorization,
  revocation, privilege isolation, and secure administrative IPC.
- Bounded processing of untrusted inputs, source-attributed evidence, privacy
  controls, retention limits, and authorized report export.
- Relevant unit/integration tests, sanitizers, static analysis, fuzzing,
  adversarial network checks, and dependency/supply-chain review.
- Documented security assessment supporting the actual release candidate.
- No unresolved release-blocking security findings at publication.

## 5. Reliability and capacity planning

M0.5 must approve quantified targets for latency, throughput, memory,
storage, recovery, and GUI performance. For **initial engineering evaluation**
only, consider 10 monitored sources (sensors and/or agents), 100 aggregate
 events/second sustained, and bursts of
1,000 events/second for a defined period. These are **not demonstrated or
promised performance capabilities**. M14 will collect reproducible evidence.

Tests should cover disconnections, bounded queues, overload and event loss
reporting, service crashes, storage constraints, and extended operation.

## 6. Release deliverables

Before v1.0.0 publication, require a reviewed source revision, tested Ubuntu
packages, installation and administration guidance, third-party notices,
license and redistribution evidence, artifact integrity hashes, dependency
inventory/SBOM, release notes, and passing qualification checks.

The release must correspond to the exact verified source and dependencies;
no untested staging artifact should be promoted implicitly.

## 7. KDE strategy and licensing

Using Qt 6, Qt Quick/QML, KDE Frameworks 6, and Kirigami from the beginning
supports KDE-style integration and GNOME compatibility, but **does not confer
official KDE status**. Incubation, KDE Invent infrastructure, localization,
and KDE Review are separate M16 objectives.

The starter repository currently uses **MIT**. M0.6 will decide and document
component-level licensing, SPDX/REUSE practice, KDE documentation and CMake
license requirements, and third-party redistribution. M0.1 does not silently
change the existing license or create a final GPL commitment.

## 8. Decisions to be closed by later issues

- **M0.2 (defined):** First-class agentless monitoring, approved LAN sensor
  and gateway sources, coverage/attribution limits, IPv4/IPv6 and
  routed-local-network authorization, encrypted LAN agent transport, opt-in
  outbound intelligence, privacy policy, and a
  [future verification matrix](../security/NETWORK_SCOPE_VERIFICATION_PLAN.md).
  Implementation of external feed synchronization must be tracked as a
  dedicated later issue; this documentation alone does not supply a client.
- **M0.3 (defined):** [Initial threat model](../security/THREAT_MODEL.md),
  [threat register](../security/THREAT_REGISTER.md), and
  [verification matrix](../security/THREAT_VERIFICATION_MATRIX.md);
  residual risk remains unassessed pending implementation and evidence.
- **M0.4:** Process boundaries, transport, APIs, and storage interfaces.
- **M0.5:** Test workloads, resource budgets, latency and capacity thresholds.
- **M0.6:** Source/documentation/build licensing and dependency review.
- **M0.7:** Mandatory build, test, and security qualification gates.
- **M13:** Security sign-off supported by evidence.
- **M14:** Performance and resilience qualification.
- **M15:** Distribution verification and release publication.

Any change to these objectives must be explicitly reviewed and reflected in
its acceptance evidence, not implemented as a silent reduction in scope.

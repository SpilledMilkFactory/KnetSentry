<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
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

M1.1 introduces the [Qt-aware CMake foundation](BUILD_FOUNDATION.md);
M1.2 adds [target-scoped hardening and sanitizers](HARDENING_AND_ANALYSIS.md).
M1.3 adds a real Qt Quick/Kirigami window and a mandatory runtime import test.
The application shell remains non-operational; navigation (M1.4), services,
and actual SIEM capabilities are future work. A passing core-only build does
not qualify the desktop or production security requirements.

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

M0.5 defines [54 traceable engineering qualification targets](PERFORMANCE_REQUIREMENTS.md),
[workload scenarios W-00–W-09](WORKLOAD_PROFILES.md), a
[28-test benchmark plan](BENCHMARK_PLAN.md), an
[evidence template](BENCHMARK_RESULT_TEMPLATE.md), a
[resource/retention capacity model](RESOURCE_CAPACITY_MODEL.md), and a
[recovery/degradation matrix](RELIABILITY_RECOVERY_PLAN.md).

The initial v1.0.0 reference targets include 10 reporting sources (with
at least one agentless source), 100 normalized events/s sustained for 60 min,
1,000 events/s burst for 60 s, separate packet-capture scenarios at 2,000
PPS sustained and 10,000 PPS burst, bounded latency/CPU/RSS, truthful loss
reporting, and 24-hour soak testing. Administrators must be able to choose a mounted local drive for raw event
records independently of the indexed SQLite database. The GUI must provide a
filesystem folder browser and the manager must validate mount identity,
permissions, raw-first durability, and failure behavior without silent fallback
onto the OS disk. See the [storage placement contract](../architecture/STORAGE_PLACEMENT_CONTRACT.md).

Seven days of event retention at these
rates can require hundreds of GiB once indexes and headroom are included;
retention must be explicitly sized rather than universally guaranteed.

**These are declared targets, not tested performance or product capabilities.**
M14 must collect reproducible release-relevant evidence. Security, source
attribution, privacy and network-scope requirements remain binding under load.

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

M0.6 adopts [MIT for KnetSentry-authored application code](LICENSING_POLICY.md)
while retaining the unchanged root MIT license. Revised Markdown documents use
CC-BY-SA-4.0; future CMake files use BSD-2-Clause. Per-file SPDX identifiers,
`LICENSES/` texts and REUSE metadata make those decisions explicit; earlier MIT
documentation grants are not revoked. [Dependency approval](DEPENDENCY_APPROVAL_POLICY.md)
and [distribution clearance](THIRD_PARTY_NOTICE_POLICY.md) remain mandatory
for each actual version and released artifact; no external Qt module, feed or
model is implicitly approved. [KDE integration criteria](KDE_COMPATIBILITY_POLICY.md)
remain separate from official KDE adoption.

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
- **M0.4 (defined):** [System architecture](../architecture/SYSTEM_ARCHITECTURE.md),
  [component catalog](../architecture/COMPONENT_CATALOG.md),
  [interface contracts](../architecture/INTERFACE_CONTRACTS.md), and
  [traceability map](../architecture/ARCHITECTURE_TRACEABILITY.md)
  establish proposed process boundaries, transport direction, typed envelopes,
  storage ownership, separate public-feed egress and Qt presentation rules.
  Interface encodings, exact privileges and implemented controls are deferred
  to their owning issues.
- **M0.5 (defined):** Test workloads, resource budgets, latency and capacity
  thresholds; implementation, measurements and final baselines remain M14 work.
- **M0.6 (defined):** Source/documentation/build licensing and dependency approval policy; actual package and redistribution audits remain future work.
- **M0.7 (defined):** [Stage-aware secure development contract](../../DEVELOPMENT_CONTRACT.md),
  [planned 30-gate verification matrix](VERIFICATION_MATRIX.md),
  [CI policy](CI_SECURITY_POLICY.md), and [evidence requirements](VERIFICATION_EVIDENCE.md);
  the real CMake/Qt/CI/security tests remain future implementation work.
- **M0.8 (defined):** [Contribution and governance rules](../../GOVERNANCE.md),
  [vulnerability reporting](../../SECURITY.md), repository templates and
  [owner setup steps](REPOSITORY_ADMIN_CHECKLIST.md). GitHub security intake
  enablement, notifications and rulesets are manual/future tasks, not passed checks.
- **M13:** Security sign-off supported by evidence.
- **M14:** Performance and resilience qualification.
- **M15:** Distribution verification and release publication.

Any change to these objectives must be explicitly reviewed and reflected in
its acceptance evidence, not implemented as a silent reduction in scope.

## M1.4 primary navigation (implementation scope)

The Qt desktop now provides a seven-section Kirigami shell with an explicit
non-operational state and headless route-testing gate. No collected security
telemetry, fake detections, network capture, or manager privileges are added.
See [M1.4 navigation requirements](GUI_NAVIGATION.md).

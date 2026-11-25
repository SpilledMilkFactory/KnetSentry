<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Documentation index

This is the authoritative navigation index for KnetSentry. The GitHub Wiki is a
published mirror of these reviewed Markdown files. Read the [project status](PROJECT_STATUS.md)
first; milestone-specific contracts record their implementation stage and are
not necessarily descriptions of the latest runtime behavior.

The engineering baseline includes 54 initial engineering requirements,
workload profiles W-00–W-09 and 28 prospective benchmark cases. These are
qualification targets, not measured results.

## Start here

- [Project status](PROJECT_STATUS.md)
- [Product Vision](../PRODUCT_VISION.md)
- [Contributor quickstart — Ubuntu 26.04 AMD64](development/CONTRIBUTOR_QUICKSTART.md)
- [Release Objectives and Acceptance Strategy](development/RELEASE_OBJECTIVES.md)
- [Wiki publishing](development/WIKI_PUBLISHING.md)

## Architecture and decisions

- [Architecture Security and Requirements Traceability](architecture/ARCHITECTURE_TRACEABILITY.md)
- [Component and Process Catalog](architecture/COMPONENT_CATALOG.md)
- [Deployment and Observability Profiles](architecture/DEPLOYMENT_TOPOLOGIES.md)
- [Logical Interface and Data Contracts](architecture/INTERFACE_CONTRACTS.md)
- [Network Communication and Observation Matrix](architecture/NETWORK_COMMUNICATION_MATRIX.md)
- [Product Scope and Deployment Boundaries](architecture/PRODUCT_SCOPE.md)
- [Storage Placement and Raw-First Event Contract](architecture/STORAGE_PLACEMENT_CONTRACT.md)
- [Modular System Architecture](architecture/SYSTEM_ARCHITECTURE.md)
- [ADR-0001 — Separate Security Domains by Operating-System Process](architecture/adr/0001-security-process-boundaries.md)
- [ADR-0002 — Preserve Source Trust, Coverage and Original Evidence](architecture/adr/0002-telemetry-trust-and-evidence.md)
- [ADR-0003 — Keep Observation, Egress and Response Authority Separate](architecture/adr/0003-network-egress-and-response.md)
- [ADR-0004 — Qt Quick/Kirigami is a Presentation Boundary](architecture/adr/0004-qt-desktop-boundaries.md)
- [ADR-0005 — Separate, Administrator-Selectable Raw Evidence Storage](architecture/adr/0005-configurable-evidence-storage.md)
- [ADR-0006 — MIT Application, REUSE Licensing, and Gated Dependencies](architecture/adr/0006-licensing-dependency-kde.md)
- [ADR-0007 — Stage-Aware Secure Development and Verification Gates](architecture/adr/0007-secure-development-gates.md)
- [ADR-0008 — Repository Governance and Coordinated Disclosure](architecture/adr/0008-repository-governance.md)

## Security and threat model

- [Network Monitoring and Communications Security Contract](security/NETWORK_SCOPE_REQUIREMENTS.md)
- [Network Scope Verification Plan](security/NETWORK_SCOPE_VERIFICATION_PLAN.md)
- [Foundational Security Principles](security/SECURITY_PRINCIPLES.md)
- [Initial Threat Model](security/THREAT_MODEL.md)
- [Initial Threat and Risk Register](security/THREAT_REGISTER.md)
- [Threat Verification and Ownership Matrix](security/THREAT_VERIFICATION_MATRIX.md)
- [Coordinated Vulnerability Handling Procedure](security/VULNERABILITY_HANDLING.md)

## Development and implementation

- [M4.1 — Agent communication protocol](development/AGENT_PROTOCOL_M41.md)
- [M4.2 — Cryptographic identity management](development/IDENTITY_M42.md)
- [Benchmark Methodology and Acceptance Plan](development/BENCHMARK_PLAN.md)
- [Benchmark Evidence Template](development/BENCHMARK_RESULT_TEMPLATE.md)
- [M1.1 — Build and Source Architecture](development/BUILD_FOUNDATION.md)
- [M1.9 — CI dependency provisioning efficiency](development/CI_EFFICIENCY_M19.md)
- [M1.8 — Ubuntu 26.04 GitHub Actions qualification](development/CI_IMPLEMENTATION_M18.md)
- [GitHub Actions and CI Security Policy](development/CI_SECURITY_POLICY.md)
- [Dependency and Supply-Chain Approval Policy](development/DEPENDENCY_APPROVAL_POLICY.md)
- [Initial Dependency Candidate Register](development/DEPENDENCY_REGISTER.md)
- [M2.9 — Global daemon toolbar and lifecycle controls](development/DESKTOP_DAEMON_TOOLBAR_M29.md)
- [M2.6 — Desktop management daemon health](development/DESKTOP_HEALTH_M26.md)
- [M3.8 — Desktop LAN scope inspection](development/DESKTOP_NETWORK_SCOPE_M38.md)
- [M3.5 — Lifecycle-only operating-system firewall profile](development/FIREWALL_ENFORCEMENT_M35.md)
- [M1.3 — Qt Quick / Kirigami Desktop Foundation](development/GUI_FOUNDATION.md)
- [M1.4 — Application Shell and Primary Navigation](development/GUI_NAVIGATION.md)
- [M1.2 — Compiler Hardening, Sanitizers and Analysis](development/HARDENING_AND_ANALYSIS.md)
- [KDE and GNOME Compatibility Policy](development/KDE_COMPATIBILITY_POLICY.md)
- [Licensing and Copyright Policy](development/LICENSING_POLICY.md)
- [M2.3 — Local authenticated IPC contract (`I-01`, `TB-05`)](development/LOCAL_AUTHENTICATED_IPC_M23.md)
- [M2.2 — Versioned manager configuration contract](development/MANAGER_CONFIGURATION_M22.md)
- [M2.1 — Management daemon lifecycle foundation](development/MANAGER_DAEMON_M21.md)
- [M3.7 — Adversarial network-boundary qualification](development/NETWORK_ADVERSARIAL_M37.md)
- [M3.4 — Fail-closed network authorization](development/NETWORK_AUTHORIZATION_M34.md)
- [M3.6 — Network isolation and policy test fixtures](development/NETWORK_ISOLATION_FIXTURES_M36.md)
- [M3.1 — Network scope policy engine](development/NETWORK_SCOPE_POLICY_M31.md)
- [M3.2 — IPv4 and IPv6 network-scope validation](development/NETWORK_SCOPE_VALIDATION_M32.md)
- [M3.3 — Linux interface and route awareness](development/NETWORK_TOPOLOGY_M33.md)
- [Performance, Reliability and Resource Requirements](development/PERFORMANCE_REQUIREMENTS.md)
- [Reliability, Recovery, and Degradation Plan](development/RELIABILITY_RECOVERY_PLAN.md)
- [Repository Security and Governance Configuration Checklist](development/REPOSITORY_ADMIN_CHECKLIST.md)
- [M1.9 — Repository metadata and contributor documentation audit](development/REPOSITORY_METADATA_M19.md)
- [Storage and Resource Capacity Model](development/RESOURCE_CAPACITY_MODEL.md)
- [C++23, Qt/QML and Security Coding Standard](development/SECURE_CODING_STANDARD.md)
- [Security Impact Review and Exception Policy](development/SECURITY_REVIEW_PROCESS.md)
- [M2.5 — Structured service audit logging](development/SERVICE_AUDIT_M25.md)
- [M2.4 — Service health and diagnostics (#21)](development/SERVICE_HEALTH_M24.md)
- [M2.8 — Service lifecycle and IPC integration](development/SERVICE_LIFECYCLE_IPC_M28.md)
- [M1.6 — Structured diagnostics and sensitive-data boundary](development/STRUCTURED_DIAGNOSTICS.md)
- [M2.7 — Initial systemd service integration and hardening](development/SYSTEMD_SERVICE_M27.md)
- [M1.7 — Initial CTest and Qt Test Suites](development/TEST_SUITE_FOUNDATION.md)
- [Third-Party Notices and Release Clearance](development/THIRD_PARTY_NOTICE_POLICY.md)
- [Toolchain, Build Presets and Test Strategy](development/TOOLCHAIN_TEST_MATRIX.md)
- [Verification Evidence and Gate Result Schema](development/VERIFICATION_EVIDENCE.md)
- [Planned Verification Gates and Ownership Matrix](development/VERIFICATION_MATRIX.md)
- [M1.5 — Visual design system](development/VISUAL_DESIGN_SYSTEM.md)
- [Reproducible Workload Profiles](development/WORKLOAD_PROFILES.md)

## Governance and contributing

- [Contributing to KnetSentry](../CONTRIBUTING.md)
- [Secure Development and Verification Contract](../DEVELOPMENT_CONTRACT.md)
- [KnetSentry Repository Governance](../GOVERNANCE.md)
- [KnetSentry Code of Conduct](../CODE_OF_CONDUCT.md)
- [KnetSentry Security Policy](../SECURITY.md)
- [Maintainer Roles and Continuity](governance/MAINTAINER_ROLES.md)
- [License](../LICENSE)

<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: MIT
-->

# KnetSentry

**Local Network Security Intelligence**

KnetSentry is a planned open-source, local-first Security Information and Event
Management (SIEM) platform for systems and security operators monitoring
**explicitly authorized devices on their own local networks**. Its intended
architecture combines a central management service, enrolled Ubuntu endpoint
agents, a security-event pipeline, detection and investigation tools, and an
optional offline AI assistant.

> **Development status — M0.1 (requirements only):** This repository currently
> contains the initial product definition. It does **not** yet include a
> functional SIEM, network collector, desktop application, detection engine, or
> production security controls. The capabilities below are *planned*, not
> implemented or security-certified.

## Intended platform and architecture

- **Initial target:** Ubuntu 26.04 LTS on AMD64/x86-64, with support for both
  GNOME and KDE Plasma desktops.
- **Implementation:** C++23 (with narrowly justified C components), CMake,
  Ninja, and a modular service/agent architecture.
- **Desktop:** Qt 6, Qt Quick/QML, KDE Frameworks 6, and Kirigami. The desktop
  is unprivileged and communicates with the management service over authorized
  local IPC; security services do not depend on GUI libraries.
- **Network:** No KnetSentry-initiated Internet communications. Connections and
  collection must stay within explicitly administrator-approved local
  interfaces, peers, and network scopes, with independent host-level policy
  enforcement. A private IP address is not by itself proof of LAN membership.
- **AI:** Optional, offline and restricted to local inference; normal SIEM
  operation must not depend on a model or a cloud provider.

## Planned security workflow

1. An administrator approves the local network scope and enrolls authorized
   endpoint agents.
2. Agents collect selected security-relevant system telemetry with the minimum
   necessary permissions and transmit it over authenticated, encrypted links.
3. The manager validates, normalizes, indexes, and retains selected events.
4. Deterministic rules and correlation logic generate traceable alerts.
5. An analyst investigates, records evidence, manages incidents, and exports
   reports. Offline AI may suggest summaries or investigative leads, but cannot
   independently take privileged response actions.

Detailed host telemetry requires an enrolled agent or an explicitly configured
telemetry source. Merely being present on the LAN does not make a device fully
observable. Passive monitoring and network-device ingestion are planned as
separate, opt-in integrations, not unrestricted discovery or interception.

## Product documentation

| Document | Purpose |
| --- | --- |
| [Product vision](PRODUCT_VISION.md) | Purpose, audiences, benefits, success criteria, and non-goals |
| [Product scope](docs/architecture/PRODUCT_SCOPE.md) | Supported deployments, boundaries, capabilities, and exclusions |
| [Security principles](docs/security/SECURITY_PRINCIPLES.md) | Trust model, mandatory controls, and security requirements |
| [Release objectives](docs/development/RELEASE_OBJECTIVES.md) | v1.0.0 release bar, milestone groups, and open decisions |

The GitHub roadmap covers M0–M15 for v1.0.0, followed by a separate optional
M16 milestone for KDE community adoption. Following KDE development guidance
does **not** imply that KnetSentry is an official KDE project.

## Development and contributions

The repository is in its documentation-first foundation stage. Build commands,
contributor instructions, automated tests, and security disclosure workflows
will be added in their scheduled milestones; do not infer that a missing test
has passed.

For now, review the four documents above and file GitHub issues for unclear,
conflicting, or untestable requirements. Security-sensitive implementation
should not begin until its relevant trust and network boundaries are defined.

## License

The repository currently uses the **MIT License**, as recorded in [LICENSE](LICENSE).
This existing license is retained for M0.1. M0.6 will document the final
component-level licensing and SPDX/REUSE policy, including KDE requirements for
source code, documentation, CMake files, and third-party assets. Changes to
license terms will be explicit and reviewed, not silently assumed.

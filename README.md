<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry

**Local Network Security Intelligence**

[![Ubuntu 26.04 CI](https://github.com/SpilledMilkFactory/KnetSentry/actions/workflows/ubuntu-26-04.yml/badge.svg?branch=main)](https://github.com/SpilledMilkFactory/KnetSentry/actions/workflows/ubuntu-26-04.yml)
[![License: MIT](https://img.shields.io/badge/code-MIT-blue.svg)](LICENSE)
[![Development status](https://img.shields.io/badge/status-pre--release-orange.svg)](docs/PROJECT_STATUS.md)

KnetSentry is an open-source, security-first, local-first SIEM platform in
development for explicitly authorized local networks. Its planned capabilities
include agentless network and gateway telemetry, optional endpoint agents,
searchable security events, deterministic detection, incident investigation,
and optional offline AI assistance.

> **Pre-release:** The management service, desktop and network-policy foundations
> are implemented. Telemetry collection, operational agent transport, event storage,
> detection and incident handling are not yet operational. Do not rely on this build
> for network protection.

## Design

- Agentless-first monitoring of approved LAN segments, including observable
  inbound and outbound traffic; external peers are not automatically enrolled or probed.
- Explicit authorization, default-deny policy, process isolation and independent
  operating-system enforcement.
- Local evidence and optional, separately authorized public intelligence access;
  no cloud or AI dependency for the core workflow.
- C++23 services and Qt 6 / Qt Quick / Kirigami desktop, with Qt-independent core logic.

## Build from source

Initial development target: **Ubuntu 26.04 LTS (AMD64)**, with GNOME or KDE
Plasma. Install the dependencies in the [contributor quickstart](docs/development/CONTRIBUTOR_QUICKSTART.md), then run:

```bash
cmake --preset linux-release
cmake --build --preset linux-release --parallel
ctest --preset linux-release --output-on-failure
./build/presets/linux-release/apps/desktop/knetsentry
```

The desktop can start and stop its own unprivileged development manager and
inspect its health and read-only policy boundary. No monitoring is activated.
Do not run the desktop or manager as root.

## Documentation

[**GitHub Wiki**](https://github.com/SpilledMilkFactory/KnetSentry/wiki) ·
[Documentation index](docs/README.md) · [Project status](docs/PROJECT_STATUS.md) ·
[Roadmap and release objectives](docs/development/RELEASE_OBJECTIVES.md)

Track development through [Issues](https://github.com/SpilledMilkFactory/KnetSentry/issues)
and [Milestones](https://github.com/SpilledMilkFactory/KnetSentry/milestones).
The repository documents are authoritative; the Wiki is a published copy.
KnetSentry is not an official KDE project.

## Contributing and security

[Contributing](CONTRIBUTING.md) · [Development contract](DEVELOPMENT_CONTRACT.md) ·
[Code of conduct](CODE_OF_CONDUCT.md) · [Governance](GOVERNANCE.md) ·
[Security policy](SECURITY.md)

Report vulnerabilities privately as described in the security policy. Never
publish private network evidence in public issues or pull requests.

## License

Application code and tooling: [MIT](LICENSE). Documentation: CC-BY-SA-4.0.
Project CMake files: BSD-2-Clause where declared. Per-file SPDX metadata and
[licensing policy](docs/development/LICENSING_POLICY.md) govern the applicable
terms; earlier license grants are retained. Third-party redistribution is
subject to separate review.

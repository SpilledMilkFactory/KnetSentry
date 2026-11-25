<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Initial Dependency Candidate Register

**Status:** Candidate inventory with scoped M4.2/M4.3 and M5.2 development-build decisions. No runtime bundle or distribution clearance has been approved. This is not a dependency lockfile.

| ID | Candidate / class | Planned use | License / constraint to verify | Future owner | Decision |
|---|---|---|---|---|---|
| `DEP-001` | Qt 6 Core / GUI / QML / Quick / Quick Controls | Desktop presentation | Exact module license and LGPLv3 obligations; do not generalize to all Qt modules | M1.3 | `CANDIDATE` |
| `DEP-002` | KDE Frameworks 6 (selected modules) | Kirigami-compatible desktop | Module-specific SPDX/license and dependencies | M1.3 | `CANDIDATE` |
| `DEP-003` | Kirigami / Kirigami Addons (if needed) | Qt Quick UI patterns | Exact KDE module, packaging and LGPL/other license | M1.3 | `CANDIDATE` |
| `DEP-004` | Extra CMake Modules (ECM) | KDE-oriented build configuration | Tooling license, package origin; custom CMake files BSD-2-Clause | M1.1 | `CANDIDATE` |
| `DEP-005` | OpenSSL 3.5.x system shared libcrypto and libssl | Offline identity and isolated mutual TLS | Apache-2.0; [identity build decision](IDENTITY_M42.md), [TLS extension](TLS_TRANSPORT_M43.md) | M4.2/M4.3 | `APPROVED_FOR_BUILD` |
| `DEP-006` | SQLite | Indexed event and metadata store | Source provenance, public-domain status/attestation and bundled components | M6.4 | `CANDIDATE` |
| `DEP-007` | Linux capture stack (e.g. libpcap) | Privileged capture broker / passive sensor | Licensing, privileges, parser security and deployment | M5.10 | `CANDIDATE` |
| `DEP-008` | systemd / distro shared libsystemd | Host service control and local journal metadata | LGPL-2.1-or-later library; component notices and installed version review; [M5.2 build decision](JOURNAL_COLLECTION_M52.md) | M2.7/M5.2 | `APPROVED_FOR_BUILD` |
| `DEP-009` | Optional network analytics (Zeek / Suricata) | Potential network telemetry adapters | Separate runtime/redistribution and copyleft implications | M9.5 | `CANDIDATE` |
| `DEP-010` | Sigma specifications / rule collections | Detection format and optional imported rules | Specification and rule-set licenses are distinct; rule corpus may restrict use | M10.6 | `CANDIDATE` |
| `DEP-011` | ATT&CK, CVE and CISA data feeds | Opt-in intelligence synchronization | Provider terms, bulk access, attribution, redistribution and API conditions | M10.9 | `CANDIDATE` |
| `DEP-012` | Offline AI inference engine and model weights | Optional local investigation assistance | Runtime code vs model weights terms, source provenance and privacy | M12.3 | `CANDIDATE` |
| `DEP-013` | Qt Graphs / other Qt GPL-only add-ons | Optional rich visualizations | **GPL-only open-source option may conflict with MIT-app distribution goal**; not an approved default | M8.2 | `REVIEW_REQUIRED` |

The `CANDIDATE` label means **not approved**. DEP-005 is limited to maintained distro 3.5.x packages for this development build; exact package versions are recorded by CI and the acceptance runner. DEP-008 is limited to distro shared libsystemd for local metadata reads; target package version review is pending. No provider, bundled artifact or release approval follows. Other candidates remain a review queue. Future distribution entries must include version/source digest, exact licenses and artifact approval evidence. Relevant security risk: `TH-031` / `TB-10` / `TV-24` in the [threat model](../security/THREAT_MODEL.md) and [verification matrix](../security/THREAT_VERIFICATION_MATRIX.md).

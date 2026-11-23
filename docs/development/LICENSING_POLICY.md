<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Licensing and Copyright Policy

**Decision:** M0.6, GitHub issue #6. **Status:** adopted for new/revised files; third-party redistribution approval remains future, evidence-based work.

## 1. Project licensing decision

KnetSentry remains an independent, MIT-licensed **application source** project. The original [root MIT grant](../../LICENSE) is unchanged. The M0.1–M0.5 documents were published with MIT SPDX notices; their earlier grants are **not revoked**. As of the M0.6 revision, documentation authors who control the rights publish the revised documentation under **CC-BY-SA-4.0**. Contributors must ensure they have the right to submit material under the applicable file license. Where provenance or rights are unclear, **do not relicense silently**; block and obtain authorization.

| Artifact class | License for KnetSentry-authored new content | Policy |
|---|---|---|
| C/C++ application, libraries, manager, agent, tests | `MIT` | Source stays permissively licensed unless a recorded, rights-cleared exception is adopted. |
| Python scripts, CLI tooling, test harnesses, REUSE metadata | `MIT` | Include SPDX header and copyright. |
| Markdown documentation, specifications, ADRs, README, user guides | `CC-BY-SA-4.0` | Include SPDX HTML comment; preserve prior published MIT grants. |
| New CMake code (including CMakeLists.txt and modules) | `BSD-2-Clause` | Required by current KDE licensing guidance; add license text only when first used. |
| Original artwork/icons | `CC-BY-SA-4.0` where rights permit | Track editable original assets and attribution; imported assets retain their own licenses. |
| Third-party source, translations, rules, feeds, model weights | **Upstream-specific** | Not automatically relicensed; approve independently before copying or redistributing. |

A root `LICENSE` is not a declaration that all files are MIT; **per-file SPDX metadata** is authoritative for explicitly differentiated materials. The MIT license contains references to software and associated documentation; previously licensed documentation remains under its original grant. This repository's new per-file notices make the prospective distribution intent explicit.

## 2. Rights and exceptions

- The copyright holder retains copyright; an open-source license is not a transfer of ownership.
- Existing public MIT grants cannot be retroactively rescinded. Do not claim exclusive new terms for previously released content.
- New third-party contributions require provenance and authorization for the chosen file license; no mandatory CLA is presumed.
- A future move from MIT to GPL/AGPL requires a reviewed ADR, ownership/consent audit and migration analysis, **not** a quiet repository-wide search-and-replace.
- MIT code is broadly compatible with many copyleft projects, but the license of an actual combined executable and its distribution obligations depend on **all** linked/bundled components.
- Linux system libraries and system-provided packages still require review of their licenses and notices when redistributed in a package.
- For new source code targeting formal KDE adoption, KDE's policy requires a copyright holder and **contact email** in source headers. The owner must designate a publication-safe contact before those files are added; do not invent or expose a private email address.

## 3. REUSE / SPDX policy

- Put an `SPDX-FileCopyrightText` and an `SPDX-License-Identifier` in each text source/doc file, using comment syntax for that file type.
- Put license text for **each actually used** SPDX license in `LICENSES/<id>.txt` (currently `MIT` and `CC-BY-SA-4.0`). Add `BSD-2-Clause.txt` when a BSD-2-Clause CMake file is first introduced; do not create unused placeholders.
- Maintain `REUSE.toml` for a file unable to embed an SPDX comment (currently the existing unmodified root `LICENSE`).
- Use standard REUSE metadata or `.license` companions for binary and third-party files; keep proof of ownership and attribution.
- Use clear SPDX expressions with `AND`/`OR` only when legally applicable, not as substitutes for review.
- Require `reuse lint` in CI from M1.8 (and before KDE Incubation/Review). Current M0.6 offline verification is **not** a substitute for running the official REUSE CLI.
- Preserve preferred editable forms of source assets, including artwork and UI resources, as required for KDE-bound contributions.
- Do not remove third-party notices, copyright statements, or license material in source or binary distributions.

## 4. License compatibility gate

Default-deny for new libraries/modules lacking a complete license and compatibility review. A GPL-only module cannot be treated as an LGPL module, and MIT source does not by itself authorize redistribution of a differently licensed combined work. Evaluate LGPL obligations, including applicable notices, shared-library replacement/relinking rights and other LGPLv3 conditions, against the **actual Qt module and distribution method**. Use system-provided dynamically linked libraries where practicable. Escalate copyleft conflicts or uncertain rights to documented review rather than assuming approval.

## 5. Source of authority and planned checks

Read the [dependency approval process](DEPENDENCY_APPROVAL_POLICY.md), [register](DEPENDENCY_REGISTER.md), [distribution notices policy](THIRD_PARTY_NOTICE_POLICY.md), and [KDE compatibility policy](KDE_COMPATIBILITY_POLICY.md). License/rights review and repository SPDX checks start here; package-level binary closure and redistribution audits are M13.7/M15.5 responsibilities.

- KDE licensing: https://community.kde.org/Policies/Licensing_Policy
- REUSE specification: https://reuse.software/spec/
- SPDX identifiers: https://spdx.org/licenses/

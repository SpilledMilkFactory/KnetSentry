<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Component and Process Catalog

> Historical baseline and design contract. For current implemented behavior and
> acceptance evidence, see [project status](../PROJECT_STATUS.md). Future requirements
> and original milestone-specific test counts below are not release claims.

**Issue:** M0.4. **Status:** proposed architecture; M2.1 implements the
`C-01` / `P-01` lifecycle foundation and M2.2 adds a strict, non-operational
configuration contract; the planned security services remain unimplemented.
See [system architecture](SYSTEM_ARCHITECTURE.md),
[interfaces](INTERFACE_CONTRACTS.md) and [security traceability](ARCHITECTURE_TRACEABILITY.md).

## 1. Component registry

Each stable `C-##` identifies a **responsibility**, not necessarily a future
binary/library name. Distinct process roles are marked `P-##`; all other
components are internal to the listed owner unless revised by security review.

| Component | Role and owned state/authority | Process allocation | Owner stage |
| --- | --- | --- | --- |
| `C-01` Manager orchestrator | Lifecycle, module wiring, health coordination; no root/capture/network policy privilege | `P-01` | M2.1 |
| `C-02` Authorization and scope-policy core | Versioned approvals for observation, service peers, provider origins, operator actions; proposes enforcement | `P-01` | M2.2/M3.1 |
| `C-03` Qt/Kirigami desktop | Operator views and accessibility; no authority except through authenticated IPC | `P-02` | M1.3/M8 |
| `C-04` CLI client | Authorized local administrative requests through same IPC contract as GUI | `P-03` | M2/M15 |
| `C-05` Capture broker | Minimum packet-socket capability for approved interfaces; bounded frame delivery; **no parsing of attacker-controlled higher-layer protocols** | `P-04` | M5.10 |
| `C-06` Passive sensor worker | Unprivileged frame validation, metadata extraction, sampling/capture-loss reporting; local relay | `P-05` | M5.10/M9.5 |
| `C-07` Gateway/export adapters | Restricted local import of configured gateway, DHCP/DNS, flow, AP/controller, or syslog exports; retains trust class | `P-06` | M5.10/M9.4 |
| `C-08` Optional host agent | Monitored-host collection, spool, health; does not acquire manager rights | `P-08` | M5.1 |
| `C-09` Restricted agent collector | Narrow host-specific protected event reads; no broad administration | `P-09` (optional) | M5.4 |
| `C-10` Telemetry transport receiver | TLS peer authentication, framing, rate limits; no manager-admin APIs and no SQL | `P-07` | M4.3 |
| `C-11` Ingestion boundary | Approval, identity-to-source binding, size/schema checks, duplicate handling, reject/quarantine disposition | `P-01` | M6.1 |
| `C-12` Normalization | OCSF-aligned typed events; raw/normalized provenance and timestamp separation | `P-01` | M6.2 |
| `C-13` Storage and retention | SQLite-backed event metadata, original-evidence references, indexes, migrations, retention and quotas | `P-01` | M6.3–M6.7 |
| `C-14` Deterministic detection | Rule state, alerts, suppression and traceable evidence links; no AI requirement | `P-01` | M7 |
| `C-15` Asset/coverage intelligence | Tentative asset relationships, attribution confidence, sensor health and coverage gaps | `P-01` | M9 |
| `C-16` Incident and response gate | Case state, human approval semantics, authorized export and narrow response requests | `P-01` | M11 |
| `C-17` Approved intelligence client | Only opt-in public feed egress and bounded content retrieval; no direct admin/database write | `P-10` | M3.9/M10.9 |
| `C-18` Optional local inference | No-network model execution; summaries/recommendations are untrusted outputs | `P-11` | M12 |
| `C-19` Audit and health | Administrative action audit, source outages, backlog, errors and coverage state | `P-01` | M1.6/M2.5 |
| `C-20` Qt presenter/models | Validated IPC projection into typed, paged `QAbstractItemModel`-style C++ models and QML | `P-02` | M1.4/M6.8 |
| `C-21` Host policy applicator | Narrow, auditable privileged apply/verify/rollback for approved capture, socket/firewall policies or response | `P-12` | M3.5/M11.5 |

**Rationale:** An unprivileged manager coordinating dedicated restricted
workers is intentionally different from a single root daemon. Each process
may have its own dedicated service identity and mandatory OS restrictions.
Specific UIDs, capabilities, file paths, cgroups, syscall filters and package
split are M2/M3/M5/M15 implementation decisions requiring review and tests.

## 2. Process privilege and networking matrix

| Process | Privilege budget (planned) | Network budget (planned) | Filesystem and secrets budget |
| --- | --- | --- | --- |
| `P-01` Manager | Service user; no root, packet capture, or firewall write | Approved collector IPC, scoped management plane and feed/AI IPC only | Managed event DB and limited state; no private agent keys |
| `P-02` Desktop | Ordinary user; no elevated capabilities | **No direct KnetSentry Internet connections**; local IPC | User UI settings, not manager DB or service credentials |
| `P-03` CLI | Ordinary/authorized local user | Local IPC only | No privileged database or raw network access |
| `P-04` Capture broker | Isolated minimal capture permission, e.g. assessed `CAP_NET_RAW`; never blanket root | Bound approved capture interfaces; no arbitrary outbound sockets | No DB, model files, or signing keys |
| `P-05` Sensor worker | Unprivileged, separately confined parser process | Local IPC (or authenticated sensor relay when remote) | Bounded memory, restricted temporary data |
| `P-06` Gateway adapter | Unprivileged; input parser isolation | Approved source bindings or local file import only | No DB writes; source config read only |
| `P-07` Transport receiver | Unprivileged separate listener service | Authorized LAN listener and local IPC; no public admin listener | TLS server identity via restricted service secrets; not CA issuing key |
| `P-08` Endpoint agent | Dedicated least-privilege service user | Approved local manager only | Local bounded spool and enrolled agent key |
| `P-09` Agent collector helper | Separate minimal read permissions/capabilities if needed | Local host-agent IPC only | Specific authorized host event sources |
| `P-10` Feed worker | Unprivileged, separate credentials and quotas | Only approved external HTTPS origins with independent egress enforcement | Approved provider configuration, bounded temporary cache; no event DB |
| `P-11` AI worker | Unprivileged, resource-limited sandbox | **No network** | Approved local model path and minimized provided context only |
| `P-12` Policy applicator | Narrowly privileged, short-lived or otherwise tightly confined | No remote network client | Verified policy changes and append-only/manager-mediated audit; no telemetry input authority |

Service-level restrictions such as `NoNewPrivileges`, `ProtectSystem`,
`RestrictAddressFamilies`, `IPAddressDeny`, and nftables are **candidate**
defense-in-depth controls; exact combinations must be validated against Ubuntu
26.04. In particular systemd socket restrictions are not a substitute for
independently enforced, tested host policy.

## 3. Dependency direction and prohibited couplings

**Allowed direction (logical, not link-library names):**

```text
P-02 / P-03  -->  I-01 local API  -->  C-01/C-02 manager
P-04 --> P-05 --> C-11; P-06 --> C-11; P-08 --> P-07 --> C-11
C-11 --> C-12 --> C-13 --> C-14 --> C-16
                          \-> C-15 --/
C-01/C-02 --> P-10 (optional feed) / P-11 (optional local AI)
C-02/C-16 --> P-12 (explicit policy/response authorization)
```

**Prohibited direct dependencies:**

- `C-03`/`C-20` -> raw capture, privileged collector, direct SQLite, OS
  firewall, private CA keys, network policy application, or inference tools.
- `C-05` -> application packet parsers, SQL, GUI, arbitrary Internet APIs.
- `C-06`/`C-07`/`C-08`/`C-10` -> privileged policy mutation, manager
  administration, or incident-response authorization.
- `C-17`/`C-18` -> manager database, security policy mutation, privileged
  response or automatic agent enrollment.
- `C-14` -> `C-18` at runtime; AI failure must not halt rule evaluation.
- Data/event content -> trusted `C-02` policy actions without a separate
  authorized administrative request.

Modules must not silently become privileged or Internet-capable for
convenience. Any exception requires an updated design decision, threat-model
review, and a specific negative test.

## 4. Dependency technology choices (not final package locks)

- **C++23 + CMake/Ninja:** shared protocols and explicit layer boundaries;
  dependency and license review belongs to M0.6, implementation to M1.
- **Qt 6/Qt Quick/QML, Kirigami, KDE Frameworks 6, ECM:** desktop-only,
  compatible with GNOME and Plasma; `QAbstractItemModel` for bounded/paged UI.
- **Linux packet capture:** assess `AF_PACKET`/libpcap and kernel filters;
  packet socket creation requires suitable privilege. Choice of capture
  backend and drop accounting stays with M5.10/M9.5.
- **TLS/PKI:** established, vetted crypto implementation, no custom
  primitives. Encoding, certificate policy and key rotation belong to M4.
- **Storage:** SQLite initial backend behind `C-13`, not exposed to QML or
  externally reachable clients; queries through manager authorization.
- **Security intelligence:** separate HTTPS feed worker (`C-17`), not generic
  event-driven URL fetching; exact provider APIs deferred to M10.9.
- **Optional inference:** independent no-network worker (`C-18`), format and
  resource decisions deferred to M12.


### M2.2 — configuration boundary (non-operational)

The `P-01` manager can validate a narrowly typed schema-v1 configuration
file before readiness; all monitoring, network, capture, public egress, and
privileged actions must remain disabled. This is **not** an implementation of
the `C-02` authorization/scoping engine or `TB-05` IPC. See the
[versioned configuration guide](../development/MANAGER_CONFIGURATION_M22.md).

### M2.3 — limited local control-plane boundary

`I-01`/`TB-05` now has a narrowly scoped opt-in Unix-domain socket and
Linux peer-credential verification. Only same UID/GID **read-only lifecycle
status** is available; administrative roles, protected operations, multiuser
authorization, and runtime service-identity confinement remain unimplemented.
See [M2.3 security contract](../development/LOCAL_AUTHENTICATED_IPC_M23.md).

## M5.1 endpoint-agent foundation

[C-08/P-08 lifecycle](../development/ENDPOINT_AGENT_SERVICE_M51.md) is now
implemented as an independent foreground process with no active collectors.
C-09/P-09 and I-07/I-09 operational communication remain unimplemented.
Production service confinement is not yet qualified.

## M5.2 local journal metadata

C-08/P-08 gains an opt-in, unit-filtered local journal metadata collector with
a protected bounded development checkpoint. C-09/P-09 and I-07/I-09 remain
undeployed. See [M5.2 journal collection](../development/JOURNAL_COLLECTION_M52.md).

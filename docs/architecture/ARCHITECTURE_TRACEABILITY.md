<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — Architecture Security and Requirements Traceability

**Issue:** M0.4. **State:** future controls and tests, not verified
mitigations. This traceability overlay maps the accepted [M0.3 threat model](../security/THREAT_MODEL.md),
[register](../security/THREAT_REGISTER.md),
[verification cases](../security/THREAT_VERIFICATION_MATRIX.md), and
[M0.2 network contract](../security/NETWORK_SCOPE_REQUIREMENTS.md)
to proposed architecture [components](COMPONENT_CATALOG.md) and
[interfaces](INTERFACE_CONTRACTS.md). It does not replace those documents.

## 1. Trust-boundary architectural ownership

| Boundary | Component owner(s) | Handoff interface(s) | Future stage | Representative verification |
| --- | --- | --- | --- | --- |
| `TB-01` | `C-02/C-05/C-15` | `I-03/I-14` | M3.1/M5.10/M9.2 | `TV-01` |
| `TB-02` | `C-07/C-11` | `I-05/I-06` | M5.10/M6.1 | `TV-02` |
| `TB-03` | `C-05/C-06` | `I-03/I-04` | M5.10/M13.6 | `TV-04` |
| `TB-04` | `C-08/C-10/C-11` | `I-07/I-08` | M4.3/M6.1 | `TV-06` |
| `TB-05` | `C-02/C-03/C-04` | `I-01/I-23` | M2.3/M13.6 | `TV-08` |
| `TB-06` | `C-11/C-12/C-14` | `I-10/I-12` | M6.1/M7.8 | `TV-10` |
| `TB-07` | `C-13/C-16/C-19` | `I-11/I-20` | M6.5/M11.8 | `TV-11` |
| `TB-08` | `C-02/C-17` | `I-15/I-16/I-17` | M3.9/M10.9 | `TV-14` |
| `TB-09` | `C-02/C-18` | `I-18` | M12.2/M12.9 | `TV-17` |
| `TB-10` | `C-01/C-19` | `I-21` | M0.6/M13.7/M15.5 | `TV-24` |
| `TB-11` | `C-02/C-21` | `I-02/I-19` | M3.5/M13.5 | `TV-09` |
| `TB-12` | `C-02/C-16` | `I-19/I-20` | M11.5/M11.8 | `TV-20` |

The M0.3 `TB-01`–`TB-12` descriptions remain authoritative; this table adds
implementation ownership without claiming deployed guards. The boundary
crossing is validated both at the consumer and, where privileged or network
traffic is involved, by independently effective operating-system controls.

## 2. Full initial threat mapping

All 42 existing tracked threats remain **Open / planned**. Future stage and
test identifiers are copied from the existing register; component attribution
is derived from the corresponding M0.3 boundary. This is a **routing index**
for reviews, not a statement that one control mitigates every attack.

| Threat | Boundary | Architecture component(s) | Primary interface(s) | M0.3 owner stage | M0.3 verification case(s) |
| --- | --- | --- | --- | --- | --- |
| `TH-001` | `TB-01` | `C-02/C-05/C-15` | `I-03/I-14` | M9.2 | `TV-02` |
| `TH-002` | `TB-01` | `C-02/C-05/C-15` | `I-03/I-14` | M5.10/M9.6 | `TV-02` |
| `TH-003` | `TB-01` | `C-02/C-05/C-15` | `I-03/I-14` | M3.1/M4.4 | `TV-01` |
| `TH-004` | `TB-02` | `C-07/C-11` | `I-05/I-06` | M5.10/M9.4 | `TV-03` |
| `TH-005` | `TB-03` | `C-05/C-06` | `I-03/I-04` | M5.10/M13.3 | `TV-04` |
| `TH-006` | `TB-02` | `C-07/C-11` | `I-05/I-06` | M6.1/M14.3 | `TV-05` |
| `TH-007` | `TB-04` | `C-08/C-10/C-11` | `I-07/I-08` | M4.2/M4.5 | `TV-06` |
| `TH-008` | `TB-04` | `C-08/C-10/C-11` | `I-07/I-08` | M4.1/M4.8 | `TV-07` |
| `TH-009` | `TB-04` | `C-08/C-10/C-11` | `I-07/I-08` | M4.3/M4.4 | `TV-06` |
| `TH-010` | `TB-05` | `C-02/C-03/C-04` | `I-01/I-23` | M2.3/M2.8 | `TV-08` |
| `TH-011` | `TB-05` | `C-02/C-03/C-04` | `I-01/I-23` | M2.7/M13.6 | `TV-27` |
| `TH-012` | `TB-11` | `C-02/C-21` | `I-02/I-19` | M3.1/M3.4 | `TV-09` |
| `TH-013` | `TB-11` | `C-02/C-21` | `I-02/I-19` | M3.3/M3.5 | `TV-09` |
| `TH-014` | `TB-06` | `C-11/C-12/C-14` | `I-10/I-12` | M6.2/M10.1 | `TV-10` |
| `TH-015` | `TB-06` | `C-11/C-12/C-14` | `I-10/I-12` | M6.1/M6.9 | `TV-10` |
| `TH-016` | `TB-07` | `C-13/C-16/C-19` | `I-11/I-20` | M6.5/M11.2 | `TV-11` |
| `TH-017` | `TB-07` | `C-13/C-16/C-19` | `I-11/I-20` | M7.5/M10.7 | `TV-12` |
| `TH-018` | `TB-12` | `C-02/C-16` | `I-19/I-20` | M11.1/M11.8 | `TV-11` |
| `TH-019` | `TB-03` | `C-05/C-06` | `I-03/I-04` | M5.10/M14.3 | `TV-13` |
| `TH-020` | `TB-08` | `C-02/C-17` | `I-15/I-16/I-17` | M3.9 | `TV-14` |
| `TH-021` | `TB-08` | `C-02/C-17` | `I-15/I-16/I-17` | M10.9/M13.3 | `TV-15` |
| `TH-022` | `TB-08` | `C-02/C-17` | `I-15/I-16/I-17` | M10.9 | `TV-15` |
| `TH-023` | `TB-08` | `C-02/C-17` | `I-15/I-16/I-17` | M3.9/M10.9 | `TV-16` |
| `TH-024` | `TB-09` | `C-02/C-18` | `I-18` | M12.6/M12.9 | `TV-17` |
| `TH-025` | `TB-09` | `C-02/C-18` | `I-18` | M12.2/M12.3 | `TV-18` |
| `TH-026` | `TB-09` | `C-02/C-18` | `I-18` | M12.2/M12.9 | `TV-19` |
| `TH-027` | `TB-12` | `C-02/C-16` | `I-19/I-20` | M11.5 | `TV-20` |
| `TH-028` | `TB-12` | `C-02/C-16` | `I-19/I-20` | M11.6/M11.8 | `TV-21` |
| `TH-029` | `TB-01` | `C-02/C-05/C-15` | `I-03/I-14` | M9.2/M10.9 | `TV-22` |
| `TH-030` | `TB-01` | `C-02/C-05/C-15` | `I-03/I-14` | M3.1/M9.5 | `TV-23` |
| `TH-031` | `TB-10` | `C-01/C-19` | `I-21` | M0.6/M13.7 | `TV-24` |
| `TH-032` | `TB-10` | `C-01/C-19` | `I-21` | M1.8/M15.5 | `TV-24` |
| `TH-033` | `TB-07` | `C-13/C-16/C-19` | `I-11/I-20` | M1.6/M13.1 | `TV-25` |
| `TH-034` | `TB-07` | `C-13/C-16/C-19` | `I-11/I-20` | M6.7/M14.4 | `TV-26` |
| `TH-035` | `TB-07` | `C-13/C-16/C-19` | `I-11/I-20` | M6.4/M14.4 | `TV-30` |
| `TH-036` | `TB-03` | `C-05/C-06` | `I-03/I-04` | M5.10/M9.5 | `TV-01` |
| `TH-037` | `TB-05` | `C-02/C-03/C-04` | `I-01/I-23` | M2.3/M11.1 | `TV-29` |
| `TH-038` | `TB-05` | `C-02/C-03/C-04` | `I-01/I-23` | M2.3/M3.5 | `TV-28` |
| `TH-039` | `TB-09` | `C-02/C-18` | `I-18` | M12.2/M13.5 | `TV-19` |
| `TH-040` | `TB-04` | `C-08/C-10/C-11` | `I-07/I-08` | M4.2/M4.5 | `TV-06` |
| `TH-041` | `TB-08` | `C-02/C-17` | `I-15/I-16/I-17` | M3.9 | `TV-14` |
| `TH-042` | `TB-06` | `C-11/C-12/C-14` | `I-10/I-12` | M7.8/M10.8 | `TV-12` |

If an interface implementation invalidates a proposed mitigation, amend the
threat register and add a negative test rather than asserting the threat has
been eliminated. A row's stage is a planned owner, not release sign-off.

## 3. Complete M0.2 network requirement ownership

All `KS-NET-001`–`KS-NET-042` are included, including agentless IoT/coverage
requirements and approved external-intelligence egress. Exact requirements
remain defined by the linked M0.2 contract.

| Requirement | Architectural owner(s) | Interface(s) | Planned stage |
| --- | --- | --- | --- |
| `KS-NET-001` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-002` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-003` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-004` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-005` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-006` | `C-02/C-15` | `I-04/I-14` | M5.10/M9.2 |
| `KS-NET-007` | `C-02/C-10` | `I-07/I-08` | M3/M4 |
| `KS-NET-031` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-032` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-033` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-034` | `C-02/C-15` | `I-04/I-14` | M5.10/M9.2 |
| `KS-NET-035` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-036` | `C-02/C-15` | `I-04/I-14` | M5.10/M9.2 |
| `KS-NET-037` | `C-02/C-15` | `I-04/I-14` | M5.10/M9.2 |
| `KS-NET-038` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-039` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-040` | `C-02/C-15` | `I-04/I-14` | M5.10/M9.2 |
| `KS-NET-041` | `C-02/C-05/C-07` | `I-03/I-05/I-06` | M3.1/M5.10 |
| `KS-NET-042` | `C-02/C-15` | `I-04/I-14` | M5.10/M9.2 |
| `KS-NET-008` | `C-02/C-10` | `I-07/I-08` | M3/M4 |
| `KS-NET-009` | `C-02/C-10` | `I-07/I-08` | M3/M4 |
| `KS-NET-010` | `C-02/C-10` | `I-07/I-08` | M3/M4 |
| `KS-NET-011` | `C-02/C-10` | `I-07/I-08` | M3/M4 |
| `KS-NET-012` | `C-02/C-10` | `I-07/I-08` | M3/M4 |
| `KS-NET-013` | `C-02/C-21` | `I-02/I-19` | M3/M13 |
| `KS-NET-014` | `C-02/C-21` | `I-02/I-19` | M3/M13 |
| `KS-NET-015` | `C-02/C-21` | `I-02/I-19` | M3/M13 |
| `KS-NET-016` | `C-02/C-17` | `I-15/I-16` | M3.9/M10.9 |
| `KS-NET-017` | `C-02/C-17` | `I-15/I-16` | M3.9/M10.9 |
| `KS-NET-018` | `C-02/C-17` | `I-15/I-16` | M3.9/M10.9 |
| `KS-NET-019` | `C-02/C-17` | `I-15/I-16` | M3.9/M10.9 |
| `KS-NET-020` | `C-02/C-17` | `I-15/I-16` | M3.9/M10.9 |
| `KS-NET-021` | `C-02/C-17` | `I-15/I-16` | M3.9/M10.9 |
| `KS-NET-022` | `C-02/C-17` | `I-15/I-16` | M3.9/M10.9 |
| `KS-NET-023` | `C-02/C-17` | `I-15/I-16` | M3.9/M10.9 |
| `KS-NET-024` | `C-02/C-17` | `I-15/I-16` | M3.9/M10.9 |
| `KS-NET-025` | `C-11/C-13` | `I-10/I-11` | M6/M11 |
| `KS-NET-026` | `C-02/C-21` | `I-02/I-19` | M3/M13 |
| `KS-NET-027` | `C-02/C-21` | `I-02/I-19` | M3/M13 |
| `KS-NET-028` | `C-02/C-21` | `I-02/I-19` | M3/M13 |
| `KS-NET-029` | `C-02/C-21` | `I-02/I-19` | M3/M13 |
| `KS-NET-030` | `C-02/C-21` | `I-02/I-19` | M3/M13 |

## 4. Acceptance and change-control rules

1. Review the `TB-##` and `TH-###` rows before implementing a process,
   listener, privileged helper, parser, provider integration or response API.
2. A changed scope, source trust level, monitoring interface, external HTTPS
   provider, privilege budget, or evidentiary claim requires a recorded
   decision and revised negative tests at the owning milestone.
3. M0.4 documents **planned controls**; actual test results, measured
   performance, deployment behavior and residual risk are deferred.
4. Absence of source telemetry, failed certificate validation, unavailable
   feeds or unsafe AI output must be represented as degraded/denied status,
   not silently treated as secure or missing data filled in.
5. Do not close any `TH-###` based solely on this architecture. Risk closure
   requires demonstrated implementation and its accepted evidence.

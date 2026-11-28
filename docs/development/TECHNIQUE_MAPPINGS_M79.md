<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M7.9 — Initial MITRE ATT&CK® technique mappings

Issue #68. Catalog revision 1, Enterprise v20 versioned references, reviewed 2026-11-27. First-party, offline rule-level investigation metadata, not verified technique occurrences, incident attribution, a coverage matrix or detection efficacy measurement. No external data download, network access, parser, dependency, persistence or new privileges. No changes to rule severity, evaluation, alert publication or evidence.

## Typed lookup

`technique_mapping(AuthenticationPattern, version)` and `technique_mapping(system_rule_id, version, audit_type)` return immutable static views. `ContextOnly` denotes an investigative association, never proof; `Unmapped` is a known rule deliberately without an association; `UnknownRule` is an unrecognized identity/version/type and never inherits metadata. Only exact known version 1 identities are supported. Maximum two associations per result; no allocations or I/O. A caller must establish finding authenticity and authorization independently. Catalog revision is separate from rule and OCSF versions. Unknown or changed versions need explicit review. Do not apply these mappings to generic rule IDs, schedule reports or persisted alerts: caller-defined rule names are not equivalent to built-in detector semantics. No GUI/IPC presentation or migration of stored alerts in this increment.

| Built-in rule | Technique / object version | Rationale and limits |
| --- | --- | --- |
| RepeatedFailures | [T1110 — Brute Force](https://attack.mitre.org/versions/v20/techniques/T1110/) / 2.8 | Repeated failures warrant investigation of access attempts; no account, origin, method or intent established. |
| SuccessAfterFailures | T1110 / 2.8; [T1078 — Valid Accounts](https://attack.mitre.org/versions/v20/techniques/T1078/) / 3.0 | A reported success after failures warrants investigation of credential attempts and possible account misuse. Receiver order is not source chronology, observations may concern different users, and compromise is not established. |
| InvalidUserObservation | Unmapped | Single invalid-user observation does not establish enumeration or credential attacks. |
| UnspecifiedActivityFailure | Unmapped | Activity is unknown; an isolated failure is insufficient. |
| audit-kernel-module (1330) | [T1547.006 — Kernel Modules and Extensions](https://attack.mitre.org/versions/v20/techniques/T1547/006/) / 1.4 | Relevant record type only; no module identity, successful operation, boot persistence, escalation or malicious intent is known. |
| All 17 other current Audit rules | Unmapped | Service start/stop alone does not show service abuse or impairment; daemon/config/netfilter/MAC changes lack direction and outcome; capability changes do not establish elevation; anomalous link/create and integrity data/metadata/status/PCR/policy/IMA observations lack action-specific proof. |

No password guessing, spraying, credential stuffing, account subtype, SSH lateral movement or rootkit subclaim is inferred. No tactic execution is inferred. Benign activity can produce every mapped observation. These associations do not alter source or collection coverage or establish absence of threats. Future evidence-rich rules require separate review rather than automatic inheritance.

## Checked numeric authentication lookup

`technique_mapping_from_code(std::int64_t, version)` accepts a signed numeric
value in the current native `AuthenticationPattern` domain. It compares the
full-width input against the four supported enumerator values and dispatches
using the corresponding named enumerator. Unknown, negative and oversized
values return `UnknownRule` with no associations; no integer-to-enum cast or
narrowing occurs. These native codes are not a stable wire or persistence
schema. Callers must validate any wider or unsigned input before converting to
this signed domain. The typed lookup remains unchanged, including its fallback
for unrecognized values. This adapter does not establish finding authenticity.

The initial M7.9 analysis build reported `EnumCastOutOfRange` for a deliberate
`static_cast<P>(999)` test. The checked adapter replaces that fixture with
explicit numeric rejection tests, including signed extremes and values that
could alias supported codes if narrowed. All four known numeric codes and
unsupported versions are also tested. No analyzer suppression is used.

## Provenance and licensing

References are MITRE Enterprise ATT&CK versioned technique pages above; object version strings are the reviewed values, not a claim to mirror a full release. Only factual IDs, names, version labels and reference URLs are used; rationales and limitations are original KnetSentry text. No third-party dataset, descriptions, logos, STIX objects or analytics are copied or bundled. MITRE ATT&CK is a registered trademark of The MITRE Corporation; no affiliation or endorsement is implied. See [Terms of Use](https://attack.mitre.org/resources/terms-of-use/) and [Legal & Branding](https://attack.mitre.org/resources/legal-and-branding/). Any future dataset import/redistribution requires the separate DEP-011 approval and applicable copyright/license notices. This does not approve a feed, TAXII/STIX integration or network egress.

## Verification

`knetsentry_technique_mappings_contract` independently verifies all four authentication identities, all 18 Audit identities, exact technique IDs, metadata, versions, explicit abstentions and refusal of mismatched identity/type, unknown numeric authentication code, unsupported version and malformed/oversized IDs. M7.8 additionally checks mapping dispositions on actual findings from both storage backends. No real telemetry or credentials. All seven presets remain mandatory; no runtime, GUI, IPC, schema, trust or authorization changes. Issues #63–#66 remain outstanding.

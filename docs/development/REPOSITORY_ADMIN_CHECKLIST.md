<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Repository Security and Governance Configuration Checklist

**Not yet verified:** do not mistake checked-in policy files for enabled GitHub settings. The following checklist records actions for the repository owner to perform and confirm using GitHub's interface. `MANUAL` means not independently verified by M0.8 tooling; `FUTURE` means the action is intentionally deferred to its owner milestone.

| Check | Operator action | Stage | M0.8 status |
| --- | --- | --- | --- |
| `GOV-01` | Confirm repository owner/visibility/branch | M0.8 | `MANUAL` |
| `GOV-02` | Verify private vulnerability reporting is enabled | M0.8 | `MANUAL` |
| `GOV-03` | Open advisory page and confirm reporter option | M0.8 | `MANUAL` |
| `GOV-04` | Configure security-alert notification delivery | M0.8 | `MANUAL` |
| `GOV-05` | Establish confidential conduct contact or document limitation | M0.8 | `MANUAL` |
| `GOV-06` | Review public issue forms and security routing | M0.8 | `STATIC` |
| `GOV-07` | Verify CODEOWNERS displays owner on PR | M0.8 | `MANUAL` |
| `GOV-08` | Confirm branch protection/rulesets staged correctly | M1.8 | `FUTURE` |
| `GOV-09` | Activate required checks only after workflows run successfully | M1.8 | `FUTURE` |
| `GOV-10` | Validate untrusted PR workflows have no secrets | M1.8 | `FUTURE` |
| `GOV-11` | Review CODEOWNERS and maintainers after membership changes | M1.9 | `FUTURE` |
| `GOV-12` | Reassess disclosure and release authority before v1.0 | M15 | `FUTURE` |

## Enable GitHub private vulnerability reporting

1. Open the [KnetSentry repository](https://github.com/SpilledMilkFactory/KnetSentry) and select **Settings**.
2. In **Security and quality**, select **Advanced Security** (GitHub may rename the navigation).
3. Find **Private vulnerability reporting** and choose **Enable**.
4. Open [Security Advisories](https://github.com/SpilledMilkFactory/KnetSentry/security/advisories) while viewing as a potential reporter and confirm that **Report a vulnerability** is available. Do not create a fake sensitive public report.
5. Configure and verify GitHub **Security alerts** notifications for the owner; test notification behavior using an appropriate harmless process rather than publishing a real vulnerability.
6. If the control is unavailable, document a legitimate alternative confidential contact before claiming the channel is operational. Do not invent an address.

## Conduct response

Set up a separate, confidential conduct channel that cannot be read by the person subject to a complaint when feasible. Record it in [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) only after it is operational; GitHub platform reporting remains available in the meantime.

## Templates, roles, and branch rules

- Confirm that Bug, Feature, and Documentation forms appear as expected; blank issues remain enabled so the owner can enter planned milestones and exceptional requests.
- Verify `.github/CODEOWNERS` requests owner review where supported. No policy file alone enforces review.
- Enable branch protection/rulesets progressively when M1 establishes actual checks. Avoid naming nonexistent required workflows or demanding a second reviewer where no such account exists.
- Keep release signing and publication authorization separate from ordinary PR checks, as specified in the [CI policy](CI_SECURITY_POLICY.md).

Record each manual action as `PASS`, `FAIL`, or `BLOCKED` in a review note only after actually performing it. The local documentation verifier intentionally reports these as **not exercised**.

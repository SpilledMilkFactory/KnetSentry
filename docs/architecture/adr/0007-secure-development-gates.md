<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0007 — Stage-Aware Secure Development and Verification Gates

**Status:** Accepted design policy (M0.7); future implementation gates not
claimed operational. **Decision owner:** KnetSentry maintainer.

## Context

KnetSentry's [M0.2 network contract](../../security/NETWORK_SCOPE_REQUIREMENTS.md),
[M0.3 threat model](../../security/THREAT_MODEL.md),
[M0.4 architecture](../SYSTEM_ARCHITECTURE.md),
[M0.5 capacity targets](../../development/PERFORMANCE_REQUIREMENTS.md), and
[M0.6 licensing policy](../../development/LICENSING_POLICY.md) establish
sensitive requirements before any C++/Qt executable exists. They need
concrete development and evidence obligations without pretending that an
unimplemented security control has passed a test.

## Decision

Adopt the root [development contract](../../../DEVELOPMENT_CONTRACT.md) with
40 traceable requirements and 30 planned verification gates. Maintain a
separate [code standard](../../development/SECURE_CODING_STANDARD.md),
[toolchain strategy](../../development/TOOLCHAIN_TEST_MATRIX.md),
[CI isolation policy](../../development/CI_SECURITY_POLICY.md), and
[review/evidence requirements](../../development/SECURITY_REVIEW_PROCESS.md).
Activate checks progressively in M1–M15, fail required applicable checks
closed, and preserve explicit PLANNED/BLOCKED/FAIL status for unfinished work.

## Alternatives considered

- **Require all tests immediately:** impossible without CMake, tests, GUI,
  packet capture or packaging; would invent assurance or block documentation.
- **Defer all standards until M13:** creates inconsistent privilege and parser
  design and late integration risk.
- **Treat green CI as release assurance:** misses field enforcement, real
  sensor visibility, distribution obligations and long-run reliability.

## Consequences and follow-up

M1.1, M1.2, M1.7, and M1.8 implement the initial toolchain and gates;
M3–M7 and M13–M15 activate domain-specific security and qualification.
Updates to privilege boundaries, LAN observation, feed egress, mounted raw
storage or optional AI must reopen relevant threat and test mappings.
M0.7's offline verifier checks document structure only; it does not
create runnable security tests or release sign-off.

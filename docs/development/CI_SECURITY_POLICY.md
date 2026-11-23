<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — GitHub Actions and CI Security Policy

**State:** M0.7 planned policy. No GitHub Actions build workflows or automated
security qualification are established by this change. M1.8 owns their
implementation; M13–M15 own deeper qualification and release gates.

## CI trust levels and event separation

1. **Pull requests from forks and unknown contributors:** treat checked-out
   code, changed YAML, PR titles/labels and artifact contents as attacker
   controlled. Use a read-only token (`contents: read`), no repository secrets,
   no privileged network interfaces, and no access to live monitoring systems.
2. **Trusted branch CI:** allow the same checks with approved dependency
   download and caching, but never automatically grant publish or signing
   authority to ordinary build jobs.
3. **Release publication:** use a separate approval-gated workflow and
   minimal elevated permissions, bound to reviewed tags/commits and qualified
   artifacts. Never publish unverified PR artifacts.
4. **Scheduled deep checks:** fuzzing, longer performance, dependency audits,
   and privileged network-isolation tests should use reviewed, appropriately
   isolated environments with accountable owners.

## Mandatory workflow safeguards

- Pin third-party `uses:` actions to reviewed full-length commit SHAs; track
  the corresponding upstream release and security updates.
- Set explicit minimal workflow/job `permissions`. Permit `id-token: write`,
  `contents: write`, or `packages: write` only in jobs that need them.
- Avoid `pull_request_target` checking out and executing untrusted PR code;
  never interpolate user-controlled GitHub event fields into shell scripts.
- Prefer ephemeral hosted runners with pinned tool/package identities where
  possible. Do not presume a hosted runner can safely grant raw packet capture,
  mount capabilities, or modification of the host network firewall.
- Require changed workflows to be reviewed as security-sensitive. Do not use
  `continue-on-error` for required checks, a final `|| true`, ignored failure
  exit codes or unconditional success on zero discovered tests.
- Treat actions caches and uploaded test artifacts as untrusted; avoid
  privilege-crossing caches, secret-bearing outputs and oversized logs.
- Never upload unredacted device traffic, user credentials, AI private
  prompts, incident evidence or real LAN telemetry to public CI.
- For checks requiring external dependency fetches, document sources and
  resolved versions. Untrusted PR code must not contact the user's LAN.
- Use appropriate timeouts, quotas, concurrency/cancellation, rate limits,
  and retention policies; unexpected timeouts remain failed/incomplete.
- Audit workflows and release keys after suspected compromise; rotate
  credentials, invalidate artifacts where necessary, and open security issues.

## Required-check activation strategy

| Stage | CI gate to introduce | Block PR? |
| --- | --- | --- |
| M0.7 | Offline Python document verification locally | Yes for M0.7 acceptance; no GitHub workflow yet |
| M1.1–M1.2 | Linux build + toolchain checks | Yes when working and reproducible |
| M1.7 | CTest, Qt Test, QML startup tests | Yes when targets exist; zero tests is failure |
| M1.8 | clang-tidy, Clazy, qmllint, formatting, official `reuse lint`, workflow-security checks | Yes after each relevant check is implemented and baselined |
| M3–M7 | Isolated network, auth, capture, protocol and event regression checks | Yes when affected surfaces are implemented and deterministic |
| M13 | Security regression qualification + regular deep fuzzing | Required in release sign-off; fast security checks on PRs |
| M14 | Sustained reliability/performance qualification | Release gate, not noisy unconditional PR gate |
| M15 | Artifact verification, clean-system install, release approval | Must pass before any v1.0.0 publish |

Branch protection must not require a check name until that workflow exists and
has demonstrated repeatable completion. Once enabled, missing results or
infrastructure failures are not automatically treated as security passes.

## Repository governance dependency

M0.8 adds the [PR template](../../.github/pull_request_template.md),
[CODEOWNERS](../../.github/CODEOWNERS), and
[manual settings checklist](REPOSITORY_ADMIN_CHECKLIST.md). These files do not
activate GitHub branch rules, private vulnerability reporting, or workflow checks.
Enable branch protection and appropriate security controls through GitHub
settings only after the affected workflows are functioning.

## References

- [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub token permissions](https://docs.github.com/en/actions/tutorials/authenticate-with-github_token)
- [REUSE specification](https://reuse.software/spec/)

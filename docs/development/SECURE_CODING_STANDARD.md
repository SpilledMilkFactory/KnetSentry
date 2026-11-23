<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# KnetSentry — C++23, Qt/QML and Security Coding Standard

**Status:** M0.7 planned requirements; coding and enforcement begin in M1.

## Core C++ / C practice

- Prefer RAII, `std::unique_ptr`, explicit owners and non-owning spans/views
  with documented lifetimes. Treat C APIs with scoped wrappers and result checks.
  Avoid shared ownership unless it is genuinely required; never hold borrowed
  storage past the owning object or request lifetime.
- Check integer arithmetic, lengths, indexes, endian conversions, structured
  data nesting, path operations and allocation sizes before use. Put explicit
  upper bounds on network frames, IPC messages, telemetry fields, queued work,
  output sizes, and file operations.
- Keep exception boundaries explicit, particularly between C callbacks,
  thread entry points and Qt signals. No exception may cross C ABI boundaries.
  Use well-defined typed errors and preserve the security-relevant cause.
- Avoid undefined behavior, raw owning pointers, unchecked array copies,
  implicit narrowing and `reinterpret_cast` on untrusted packet structures.
  Only allow targeted exceptions with rationale and tests.
- No custom cryptographic primitives or casual TLS verification bypasses.
  Keys and tokens must not enter logs, exceptions, telemetry exports or QML.
- Check filesystem objects using the approved dirfd/handle model where
  necessary; do not assume paths are safe after a single path-string check.
  Reject symlinks, traversal and mount substitutions in protected storage
  according to the M0.5 storage contract.

## Trust, memory and concurrency

- Passive packets, gateway records, external intelligence, model outputs,
  operator-supplied paths, agent data and local IPC are untrusted until
  their *specific* validation and authorization checks succeed.
- Do not confuse authenticated transport with trustworthy telemetry values
  or with confirmed identity of a passive device.
- Declare thread ownership, object lifetime, lock order, queue bounds,
  graceful cancellation and shutdown deadlines. Never block the Qt GUI event
  loop with unbounded I/O or cryptographic parsing.
- Privileged capture brokers must not interpret rich protocol payloads.
  Unprivileged workers perform bounded packet parsing; Qt frontend must not
  use root or directly write protected evidence stores.
- Validate at every authority boundary, not only at the original entry point.
  A rule engine or AI suggestion cannot authorize response actions.

## Qt 6 / Kirigami / QML

- Keep business logic and security decisions in tested native C++ services;
  use typed Qt models for view data and minimal QML presentation logic.
- Never expose credentials, filesystem handles or privileged service methods
  through unrestricted QML context properties or invokable objects.
- Validate parameters again in the daemon when a GUI issues an admin request;
  a disabled button is *not* authorization.
- Handle asynchronous response and cancellation safely; verify model reset,
  index lifetime, `QObject` parentage, thread affinity and queued signals.
- Use accessible names, keyboard focus, scaling and reduced-motion options;
  handle rendering and plugin failures without claiming the SIEM is offline.
- Run `qmllint` and Qt Quick Test once relevant QML modules exist; use Clazy
  for Qt C++, clang-tidy for appropriate first-party C++ targets.

## Security code review questions

For new parsing/storage/network/authentication/response/AI logic, reviewers
must identify the entry point, attacker-controlled fields, privilege crossing,
limits, negative-case tests, failure mode, audit/telemetry effect, and release
risk. Record any new `TH-*` risk or explain why existing threat coverage
remains sufficient. See [security review process](SECURITY_REVIEW_PROCESS.md).

The standard intentionally does not mandate a particular formatting profile or
C++ static-analyzer version before M1 adopts and validates one; those choices
will be pinned in the repository, not silently inherited from a developer IDE.

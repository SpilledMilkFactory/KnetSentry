#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline registration and structural privacy controls; runtime evidence separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_privacy_policy_contract'
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    agent = (ROOT / 'apps/agent/agent_main.cpp').read_text()
    policy = (ROOT / 'apps/agent/privacy.cpp').read_text()
    native = (ROOT / 'src/agent/systemd_journal.cpp').read_text()
    journal = (ROOT / 'src/agent/journal.cpp').read_text()
    fim = (ROOT / 'src/agent/fim.cpp').read_text()
    if name not in CORE_TESTS or f'NAME {name}' not in tests:
        raise ValueError('missing mandatory M5.7 regression')
    if not agent.index('restrict_privileges();') < agent.index('authorize_privacy(') < agent.index('make_journal_source('):
        raise ValueError('privacy policy not before collector construction')
    for marker in ('allow-unit', 'deny-unit', 'allow-path', 'deny-path', 'permit', 'redact', 'EVP_sha256()'):
        if marker not in policy:
            raise ValueError('missing policy control: ' + marker)
    if not native.index('if (redact_auth_)') < native.index('"MESSAGE"'):
        raise ValueError('authentication redaction must precede message access')
    if not fim.index('if (!read_content)') < fim.index('File reader('):
        raise ValueError('metadata-only FIM must precede content access')
    if 'KNETSENTRY-PRIVACY-V1' not in journal or 'privacy_fingerprint_' not in journal:
        raise ValueError('missing policy-bound state')
    if 'PRIVACY_MINIMIZATION_M57.md' not in (ROOT / 'docs/README.md').read_text():
        raise ValueError('missing documentation index')
    print('M5.7 explicit policy and acquisition-time redaction registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

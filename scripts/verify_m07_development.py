#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Check M0.7 requirements, gate IDs, owners and links; no runtime tests run."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
ERRORS: list[str] = []
REQUIRED = (
    'DEVELOPMENT_CONTRACT.md',
    'docs/development/SECURE_CODING_STANDARD.md',
    'docs/development/TOOLCHAIN_TEST_MATRIX.md',
    'docs/development/CI_SECURITY_POLICY.md',
    'docs/development/SECURITY_REVIEW_PROCESS.md',
    'docs/development/VERIFICATION_EVIDENCE.md',
    'docs/development/VERIFICATION_MATRIX.md',
    'docs/architecture/adr/0007-secure-development-gates.md',
    'README.md', 'docs/development/RELEASE_OBJECTIVES.md',
    'docs/security/SECURITY_PRINCIPLES.md',
    'docs/development/DEPENDENCY_APPROVAL_POLICY.md',
)


def check(condition: bool, reason: str) -> None:
    if not condition:
        ERRORS.append(reason)


def read(path: str) -> str:
    f = ROOT / path
    if not f.is_file():
        ERRORS.append(f'missing file: {path}')
        return ''
    return f.read_text(encoding='utf-8')


texts = {file: read(file) for file in REQUIRED}
header = ('<!--\nSPDX-FileCopyrightText: 2026 Chris Sutton\n'
          'SPDX\x2dLicense-Identifier: CC-BY-SA-4.0\n-->')
for file, content in texts.items():
    check(content.startswith(header), f'{file}: SPDX documentation header missing')
    check(len(content) > 300, f'{file}: suspiciously short')
    source = ROOT / file
    for raw_link in re.findall(r'(?<!!)\[[^]]+\]\(([^)]+)\)', content):
        target = raw_link.split(' ', 1)[0]
        parsed = urlparse(target)
        if parsed.scheme or parsed.netloc or not parsed.path or parsed.path.startswith('/'):
            continue
        resolved = (source.parent / unquote(parsed.path)).resolve()
        check(resolved.is_relative_to(ROOT) and resolved.is_file(),
              f'{file}: broken internal link: {raw_link}')

contract = texts['DEVELOPMENT_CONTRACT.md']
rows = re.findall(
    r'^\| `KS-DEV-(\d{3})` \| ([^|]+) \| ([^|]+) \| '
    r'(M\d+\.\d+) \| `(VG-\d{2})` \|$', contract, flags=re.M)
ids = [id for id, *_ in rows]
check(len(rows) == 40 and len(set(ids)) == 40, 'expected exactly 40 unique requirement rows')
check(set(ids) == {f'{i:03}' for i in range(1, 41)}, 'missing/gapped KS-DEV identifiers')

matrix = texts['docs/development/VERIFICATION_MATRIX.md']
gates = re.findall(
    r'^\| `VG-(\d{2})` \| ([^|]+) \| (M\d+\.?\d*(?:/M\d+\.\d+)?)'
    r' \| ([^|]+) \| ([^|]+) \|$', matrix, flags=re.M)
gate_ids = [gid for gid, *_ in gates]
check(len(gates) == 30 and len(set(gate_ids)) == 30,
      'expected exactly 30 unique gate rows')
check(set(gate_ids) == {f'{i:02}' for i in range(1, 31)},
      'missing/gapped VG identifiers')
check(set(g for *_,g in rows) == {f'VG-{i:02}' for i in range(1,31)},
      'every gate must be referenced by at least one development requirement')
for id, topic, req, owner, gate in rows:
    check(len(topic.strip()) >= 5 and len(req.strip()) >= 35,
          f'KS-DEV-{id}: incomplete topic/requirement')
    check(gate[3:] in gate_ids, f'KS-DEV-{id}: missing gate {gate}')
    check(0 <= int(owner[1:].split('.')[0]) <= 16,
          f'KS-DEV-{id}: owner outside roadmap')
for gid, scope, owner, outcome, evidence in gates:
    check(len(scope.strip()) >= 6 and len(outcome.strip()) >= 12
          and len(evidence.strip()) >= 10,
          f'VG-{gid}: incomplete verification specification')

coding = texts['docs/development/SECURE_CODING_STANDARD.md']
for phrase in ('RAII', 'Qt 6', 'untrusted', 'agent', 'privilege', 'storage',
               'QML', 'concurrency'):
    check(phrase.lower() in coding.lower(), f'coding standard missing {phrase}')
tool = texts['docs/development/TOOLCHAIN_TEST_MATRIX.md']
for phrase in ('linux-release', 'linux-sanitize', 'CTest', 'Qt Test',
               'Qt Quick Test', 'clang-tidy', 'Clazy', 'qmllint', 'ASan',
               'UBSan', 'fuzz', 'nftables'):
    check(phrase.lower() in tool.lower(), f'toolchain matrix missing {phrase}')
ci = texts['docs/development/CI_SECURITY_POLICY.md']
for phrase in ('pull_request_target', 'contents: read', 'secrets',
               'full-length commit SHA', 'permissions', 'zero',
               'privileged', 'M1.8', 'M15'):
    check(phrase.lower() in ci.lower(), f'CI policy missing {phrase}')
evidence = texts['docs/development/VERIFICATION_EVIDENCE.md']
for state in ('PLANNED', 'PASS', 'FAIL', 'BLOCKED', 'NOT_APPLICABLE', 'EXCEPTION'):
    check(f'`{state}`' in evidence, f'evidence missing state {state}')
for phrase in ('source', 'command', 'expected', 'observed', 'environment',
               'independent', 'review', 'artifact'):
    check(phrase.lower() in evidence.lower(), f'evidence missing field {phrase}')
review = texts['docs/development/SECURITY_REVIEW_PROCESS.md']
for phrase in ('TB-*', 'TH-*', 'privacy', 'Critical', 'High', 'Moderate',
               'Low', 'UNASSESSED', 'expiry', 'self-review'):
    check(phrase.lower() in review.lower(), f'security review missing {phrase}')
for path in ('README.md', 'docs/development/RELEASE_OBJECTIVES.md',
             'docs/security/SECURITY_PRINCIPLES.md'):
    check('DEVELOPMENT_CONTRACT.md' in texts[path],
          f'{path}: not linked to new development contract')
check('M0.7' in texts['docs/architecture/adr/0007-secure-development-gates.md'],
      'ADR-0007 must record M0.7 decision')
check('not yet implemented' in contract.lower() or 'not implemented' in contract.lower(),
      'contract must not imply active build gates')
for script in sorted((ROOT / 'scripts').glob('verify_m*.py')):
    s = script.read_text(encoding='utf-8')
    check('# SPDX\x2dLicense-Identifier: MIT' in s[:180],
          f'{script.name}: MIT tooling SPDX header missing')

if ERRORS:
    print('M0.7 development-contract verification: FAIL', file=sys.stderr)
    for problem in ERRORS:
        print(f'  - {problem}', file=sys.stderr)
    sys.exit(1)
print('M0.7 development-contract verification: PASS')
print('  40 traceable KS-DEV requirements; 30 planned VG verification gates')
print('  C++23/Qt, sanitizers, Clazy, QML, CI, fuzzing and review stages mapped')
print('  Planned future test gates are not reported as implemented or passed')

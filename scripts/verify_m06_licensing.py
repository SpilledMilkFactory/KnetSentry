#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M0.6 offline licensing-policy consistency verifier.

This is NOT the official `reuse lint` tool, a dependency audit, a legal
opinion, or an actual artifact-redistribution clearance.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
ERRORS: list[str] = []
DOC = 'CC-BY-SA-4.0'
SOURCE = 'MIT'
FILES = {
    'LICENSE', '.gitignore', 'REUSE.toml',
    'LICENSES/MIT.txt', 'LICENSES/CC-BY-SA-4.0.txt',
    'docs/development/LICENSING_POLICY.md',
    'docs/development/DEPENDENCY_APPROVAL_POLICY.md',
    'docs/development/DEPENDENCY_REGISTER.md',
    'docs/development/KDE_COMPATIBILITY_POLICY.md',
    'docs/development/THIRD_PARTY_NOTICE_POLICY.md',
    'docs/architecture/adr/0006-licensing-dependency-kde.md',
}

def check(condition: bool, reason: str) -> None:
    if not condition:
        ERRORS.append(reason)

def read(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        ERRORS.append(f'missing file: {rel}')
        return ''
    return p.read_text(encoding='utf-8')

for rel in sorted(FILES):
    read(rel)

license_file = read('LICENSE')
check(license_file.startswith('MIT License\n'), 'root LICENSE is not MIT')
check('Copyright (c) 2026 Chris Sutton' in license_file, 'root copyright changed')
check(read('LICENSES/MIT.txt') == license_file,
      'LICENSES/MIT.txt differs from existing MIT license text')
cc = read('LICENSES/CC-BY-SA-4.0.txt')
check(len(cc) >= 14000 and 'Section 1' in cc and 'Section 8' in cc
      and 'Creative Commons' in cc, 'CC-BY-SA-4.0 license text incomplete')
reuse = read('REUSE.toml')
try:
    cfg = tomllib.loads(reuse)
    check(cfg.get('version') == 1, 'REUSE.toml version must be 1')
    check(any(a.get('path') == ['LICENSE'] and a.get('precedence') == 'override'
              and a.get('SPDX-License-Identifier') == 'MIT'
              for a in cfg.get('annotations', [])),
          'missing MIT declaration for unchanged LICENSE')
except (ValueError, TypeError) as exc:
    ERRORS.append(f'invalid REUSE.toml: {exc}')

mds = sorted([ROOT / 'README.md', ROOT / 'PRODUCT_VISION.md',
              *(ROOT / 'docs').rglob('*.md')])
for f in mds:
    rel = f.relative_to(ROOT)
    s = f.read_text(encoding='utf-8')
    check(s.startswith('<!--\nSPDX-FileCopyrightText: 2026 Chris Sutton\n'
                       'SPDX\x2dLicense-Identifier: CC-BY-SA-4.0\n-->'),
          f'{rel}: missing documentation SPDX header')
    for raw in re.findall(r'(?<!!)\[[^]]+\]\(([^)]+)\)', s):
        target = raw.split(' ', 1)[0]
        parsed = urlparse(target)
        if parsed.scheme or parsed.netloc or not parsed.path or parsed.path.startswith('/'):
            continue
        resolved = (f.parent / unquote(parsed.path)).resolve()
        check(resolved.is_relative_to(ROOT.resolve()) and resolved.is_file(),
              f'{rel}: broken internal link {raw}')

scripts = sorted((ROOT / 'scripts').glob('*.py'))
for f in scripts:
    s = f.read_text(encoding='utf-8')
    check('# SPDX-FileCopyrightText: 2026 Chris Sutton' in s[:220]
          and '# SPDX\x2dLicense-Identifier: MIT' in s[:220],
          f'{f.relative_to(ROOT)}: missing tooling SPDX header')
for rel in ('.gitignore', 'REUSE.toml'):
    s = read(rel)
    check('# SPDX\x2dLicense-Identifier: MIT' in s[:250], f'{rel}: missing SPDX header')

policy = read('docs/development/LICENSING_POLICY.md')
for need in ('BSD-2-Clause', 'CC-BY-SA-4.0', 'MIT',
             'previously licensed', 'reuse lint', 'earlier grants'):
    check(need.lower() in policy.lower(), f'license policy missing {need!r}')
reg = read('docs/development/DEPENDENCY_REGISTER.md')
rows = re.findall(r'^\| `(DEP-\d{3})` \|.*\| `(CANDIDATE|REVIEW_REQUIRED|APPROVED_FOR_BUILD|APPROVED_FOR_DISTRIBUTION|REJECTED|RETIRED)` \|$', reg, re.M)
ids = [id for id, _ in rows]
check(len(ids) == len(set(ids)) == 13, 'expected 13 unique dependency candidates')
check(set(ids) == {f'DEP-{i:03}' for i in range(1, 14)}, 'dependency IDs missing')
check(all(status == 'APPROVED_FOR_BUILD' if dep == 'DEP-005' else
          status in ('CANDIDATE', 'REVIEW_REQUIRED') for dep, status in rows),
      'unexpected dependency approval outside the M4.2 scoped decision')
check('IDENTITY_M42.md' in reg and 'Apache-2.0' in reg, 'missing DEP-005 build evidence')
check('Qt Graphs' in reg and 'GPL-only' in reg,
      'missing Qt GPL-only module warning')
for rel in ('docs/development/DEPENDENCY_APPROVAL_POLICY.md',
            'docs/development/KDE_COMPATIBILITY_POLICY.md',
            'docs/development/THIRD_PARTY_NOTICE_POLICY.md'):
    check(len(read(rel)) >= 600, f'{rel}: unexpectedly incomplete')
check('LICENSE' in read('README.md') and 'MIT' in read('README.md')
      and 'CC-BY-SA-4.0' in read('README.md'), 'README lacks mixed-license summary')
# Check that the existing accepted traceability registers remain present,
# without claiming that any future implementation or release is approved.
for rel in ('docs/security/THREAT_REGISTER.md',
            'docs/security/THREAT_VERIFICATION_MATRIX.md',
            'docs/architecture/ARCHITECTURE_TRACEABILITY.md'):
    check((ROOT / rel).is_file(), f'missing baseline traceability: {rel}')

if ERRORS:
    print('M0.6 licensing documentation verification: FAIL', file=sys.stderr)
    for err in ERRORS:
        print(f'  - {err}', file=sys.stderr)
    sys.exit(1)
print('M0.6 licensing documentation verification: PASS')
print(f'  {len(mds)} documented Markdown files; {len(scripts)} MIT Python tools')
print('  MIT application policy; CC-BY-SA-4.0 docs; future BSD-2-Clause CMake')
print('  13 dependency entries, one scoped build approval, zero approved bundles; release clearance pending')
print('  Offline policy checks only; official reuse lint and artifact audits pending')

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Check M0.8 governance documents/forms. Does not inspect GitHub account settings."""
from __future__ import annotations
import re
import sys
from pathlib import Path
from urllib.parse import urlparse, unquote

ROOT = Path(__file__).resolve().parent.parent
ERRORS: list[str] = []
DOCS = [
    'README.md', 'GOVERNANCE.md', 'CONTRIBUTING.md',
    'SECURITY.md', 'CODE_OF_CONDUCT.md',
    'docs/governance/MAINTAINER_ROLES.md',
    'docs/security/VULNERABILITY_HANDLING.md',
    'docs/development/REPOSITORY_ADMIN_CHECKLIST.md',
    'docs/architecture/adr/0008-repository-governance.md',
    '.github/pull_request_template.md',
]
YAML = [
    '.github/ISSUE_TEMPLATE/config.yml',
    '.github/ISSUE_TEMPLATE/bug_report.yml',
    '.github/ISSUE_TEMPLATE/feature_request.yml',
    '.github/ISSUE_TEMPLATE/documentation.yml',
]
HEADER='<!--\nSPDX-FileCopyrightText: 2026 Chris Sutton\nSPDX\x2dLicense-Identifier: CC-BY-SA-4.0\n-->\n'
def check(ok: bool, msg: str) -> None:
    if not ok: ERRORS.append(msg)
def read(path: str) -> str:
    p=ROOT/path
    if not p.is_file():
        ERRORS.append('missing file: '+path)
        return ''
    return p.read_text(encoding='utf-8')
texts={p:read(p) for p in DOCS}
for p,s in texts.items():
    check(s.startswith(HEADER), p+': missing CC-BY-SA-4.0 header')
    check(len(s)>200, p+': incomplete document')
    f=ROOT/p
    for target in re.findall(r'(?<!!)\[[^]]+\]\(([^)]+)\)',s):
        link=target.split(' ',1)[0]
        u=urlparse(link)
        if u.scheme or u.netloc or not u.path or u.path.startswith('/'): continue
        resolved=(f.parent/unquote(u.path)).resolve()
        check(resolved.is_relative_to(ROOT.resolve()) and resolved.is_file(),
              p+': broken link '+link)
for p in YAML:
    s=read(p)
    check(s.startswith('# SPDX-FileCopyrightText: 2026 Chris Sutton\n# SPDX\x2dLicense-Identifier: MIT'),
          p+': missing YAML SPDX declaration')
    check(len(s)>200,p+': incomplete YAML')
    check('SECURITY.md' in s or 'security/advisories' in s, p+': missing vulnerability routing warning')
    if p.endswith('config.yml'):
        check('blank_issues_enabled: true' in s, 'config: existing planning issues must remain possible')
        check('contact_links:' in s and 'security/advisories' in s,
              'config: missing security advisory routing')
    else:
        for part in ('name:', 'description:', 'labels:', 'body:'):
            check(re.search(r'^'+part,s,re.M) is not None,p+': missing '+part)
        check('type:' in s and 'id:' in s and 'attributes:' in s,
              p+': form needs typed fields with IDs')
expected={'bug_report.yml':'type:bug','feature_request.yml':'type:feature','documentation.yml':'type:documentation'}
for name, label in expected.items():
    check(label in read('.github/ISSUE_TEMPLATE/'+name),name+': wrong issue label')
codeowners=read('.github/CODEOWNERS')
check('# SPDX\x2dLicense-Identifier: MIT' in codeowners[:200], 'CODEOWNERS: missing license')
check('* @SpilledMilkFactory' in codeowners, 'CODEOWNERS: missing main owner')
check('self-review' in codeowners.lower(), 'CODEOWNERS: no independence warning')
register=texts['GOVERNANCE.md']
rows=re.findall(r'^\| `KS-GOV-(\d{3})` \| ([^|]+) \| ([^|]+) \| `(GOV-\d{2})` \|$',register,re.M)
ids=[x[0] for x in rows]
check(len(rows)==20 and set(ids)=={f'{n:03}' for n in range(1,21)},
      'expected 20 unique, consecutive KS-GOV requirement IDs')
check(len(ids)==len(set(ids)), 'duplicate KS-GOV requirement')
checks=texts['docs/development/REPOSITORY_ADMIN_CHECKLIST.md']
items=re.findall(r'^\| `GOV-(\d{2})` \| ([^|]+) \| ([^|]+) \| `(MANUAL|FUTURE|STATIC)` \|$', checks,re.M)
gates=[item[0] for item in items]
check(len(items)==12 and set(gates)=={f'{n:02}' for n in range(1,13)},
      'expected 12 unique, consecutive GOV verification checkpoints')
check(len(gates)==len(set(gates)), 'duplicate GOV checkpoint')
for ident,topic,req,gate in rows:
    check(len(topic.strip())>8 and len(req.strip())>45,
          'KS-GOV-'+ident+': incomplete requirement')
    check(gate[4:] in gates, 'KS-GOV-'+ident+': unknown checkpoint '+gate)
for p in ('SECURITY.md','docs/security/VULNERABILITY_HANDLING.md','docs/development/REPOSITORY_ADMIN_CHECKLIST.md'):
    s=texts[p].lower()
    for term in ('private', 'advisori', 'public', 'not', 'report'):
        check(term in s,p+': missing security intake qualifier '+term)
for p in ('CONTRIBUTING.md','GOVERNANCE.md','CODE_OF_CONDUCT.md','SECURITY.md'):
    check(p in texts['README.md'], 'README missing governance link: '+p)
for term in ('not yet', 'settings', 'enable', 'report a vulnerability'):
    check(term in checks.lower(), 'admin checklist missing manual setup: '+term)
for term in ('MIT','CC-BY-SA-4.0','independent','self-review'):
    check(term.lower() in texts['CONTRIBUTING.md'].lower()+register.lower(),
          'policy missing: '+term)
check('M0.8' in texts['docs/architecture/adr/0008-repository-governance.md'],
      'ADR-0008 lacks milestone decision')
for p in ('LICENSE','.gitignore','DEVELOPMENT_CONTRACT.md','scripts/verify_m07_development.py'):
    check((ROOT/p).is_file(), 'baseline file missing '+p)
if ERRORS:
    print('M0.8 governance verification: FAIL',file=sys.stderr)
    for e in ERRORS: print('  - '+e,file=sys.stderr)
    sys.exit(1)
print('M0.8 governance verification: PASS')
print('  20 traceable KS-GOV requirements; 12 GitHub setup/verification checkpoints')
print('  3 public issue forms, 1 chooser config, PR template, CODEOWNERS')
print('  Policy/structure only; private reporting and branch settings NOT verified')

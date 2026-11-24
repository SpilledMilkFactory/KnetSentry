#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline M0.5 documentation and storage placement consistency checks.

Does not benchmark implemented software or validate actual storage controls.
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
FILES={
 'requirements': 'docs/development/PERFORMANCE_REQUIREMENTS.md',
 'benchmarks': 'docs/development/BENCHMARK_PLAN.md',
 'workloads': 'docs/development/WORKLOAD_PROFILES.md',
 'failures': 'docs/development/RELIABILITY_RECOVERY_PLAN.md',
 'capacity': 'docs/development/RESOURCE_CAPACITY_MODEL.md',
 'template': 'docs/development/BENCHMARK_RESULT_TEMPLATE.md',
 'storage': 'docs/architecture/STORAGE_PLACEMENT_CONTRACT.md',
 'adr': 'docs/architecture/adr/0005-configurable-evidence-storage.md',
 'readme': 'README.md',
 'release': 'docs/development/RELEASE_OBJECTIVES.md',
}
errors=[]
text={}
for name,rel in FILES.items():
 p=ROOT/rel
 if not p.is_file(): errors.append(f'missing: {rel}');continue
 s=p.read_text(encoding='utf-8');text[name]=s
 if name not in ('readme','release') and 'SPDX\x2dLicense-Identifier: CC-BY-SA-4.0' not in s:
  errors.append(f'missing SPDX marker in {rel}')

def find_rows(name,prefix,nums):
 s=text.get(name,'')
 ids=[int(n) for n in re.findall(r'^\| `'+re.escape(prefix)+r'(\d+)` \|',s,re.M)]
 required=set(nums)
 if len(ids)!=len(set(ids)):errors.append(f'duplicate {prefix} IDs')
 if set(ids)!=required:
  errors.append(f'{name}: {prefix} IDs expected {min(required)}..{max(required)} ({len(required)}); actual {sorted(ids)}')
 return ids

req=find_rows('requirements','KS-PERF-',range(1,55))
bench=find_rows('benchmarks','BT-',range(1,29))
work=find_rows('workloads','W-',range(0,10))
fail=find_rows('failures','F-',range(1,19))
# Every performance requirement row must reference an actual benchmark
for line in text.get('requirements','').splitlines():
 if not line.startswith('| `KS-PERF-'):continue
 parts=[x.strip() for x in line.split('|')]
 ids=re.findall(r'`BT-(\d+)`',line)
 if len(ids)!=1 or int(ids[0]) not in bench:
  errors.append(f'missing benchmark link for requirement: {parts[1]}')
 # finite obligation and future owner (may be combined M6.3/M14.4)
 if not re.search(r'\bM\d+(?:\.\d+)?\b',line):
  errors.append(f'missing milestone owner: {parts[1]}')

for num in range(41,55):
 id=f'KS-PERF-{num:03d}'
 if id not in text.get('benchmarks',''):
  errors.append(f'no benchmark mapped for {id}')
for id in ('BT-22','BT-23','BT-24','BT-25','BT-26','BT-27','BT-28'):
 if id not in text.get('storage','') and id not in text.get('benchmarks',''):
  errors.append(f'missing new test {id}')

must={
 'storage': ['Qt', 'another local drive', 'before', 'INDEX_PENDING',
             'OS', 'filesystem', 'removable', 'authorization', 'mount'],
 'capacity': ['2,048','123,863,040,000','No quiet spillover', 'per volume', 'SQLite'],
 'workloads': ['W-08','W-09','agentless'],
 'failures': ['F-13','F-18','no', 'mount'],
 'template': ['Raw volume identity', 'KS-PERF-041..054'],
 'readme': ['54 initial engineering requirements','W-00–W-09', '28 prospective benchmark'],
 'requirements': ['No silent OS fallback','Raw-first pipeline','Separate index location'],
}
for name, phrases in must.items():
 s=text.get(name,'')
 for phrase in phrases:
  if phrase not in s: errors.append(f'{name}: missing expected phrase {phrase!r}')
# Verify relative local Markdown links in all touched documentation files
for name,rel in FILES.items():
 if name not in text:continue
 s=text[name]
 for target in re.findall(r'(?<!!)\[[^\]]+\]\(([^)]+)\)',s):
  target=target.split('#',1)[0].split('?',1)[0]
  if not target or re.match(r'^[a-z][\w+.-]*:',target) or target.startswith('/'):
   continue
  dest=(ROOT/rel).parent/target
  if not dest.is_file(): errors.append(f'broken local link in {rel}: {target}')
# Don't claim to have benchmarked a future architecture.
for name in ('requirements','benchmarks','workloads','failures','capacity','template','storage'):
 if re.search(r'(?im)^.*\bmeasured and passed\b',text.get(name,'')):
  errors.append(f'unverified status phrased as implemented in {name}')
if errors:
 print('M0.5 documentation verification: FAIL',file=sys.stderr)
 for e in errors: print(' - '+e,file=sys.stderr)
 sys.exit(1)
print('M0.5 documentation verification: PASS')
print('  54 traceable qualification requirements; 10 workload profiles (W-00..W-09)')
print('  28 future benchmark cases, 18 future failure/recovery cases')
print('  Raw event storage and SQLite indexes independently selectable; mount-safe policy specified')
print('  All performance/storage controls remain design requirements, not measured results')

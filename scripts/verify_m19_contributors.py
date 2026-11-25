#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.9 offline contributor docs and CI provisioning gate.

Passing this verifier is not proof of a fresh Ubuntu 26.04 build or GitHub CI.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / 'scripts/ci/install_dependencies.sh'
PRESETS = {
    'linux-release', 'linux-debug', 'linux-sanitize', 'linux-clazy',
    'linux-analysis', 'linux-core-only', 'linux-sanitize-core-only',
}
BASIC = {'build-essential', 'cmake', 'ninja-build', 'python3'}
DESKTOP = {'qt6-base-dev', 'qt6-declarative-dev', 'libkirigami-dev',
           'qml6-module-org-kde-kirigami', 'qml6-module-qtquick-controls'}


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding='utf-8')


def check_profiles() -> None:
    subprocess.run(['bash', '-n', str(HELPER)], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    packages = {}
    for profile in sorted(PRESETS | {'qml', 'policy'}):
        proc = subprocess.run(['bash', str(HELPER), profile, '--list'],
                              capture_output=True, text=True, check=True)
        lines = proc.stdout.splitlines()
        require(bool(lines) and len(lines) == len(set(lines)),
                f'{profile}: empty or duplicate package list')
        require(all(re.fullmatch(r'[a-z0-9][a-z0-9.+-]*', x) for x in lines),
                f'{profile}: invalid package name')
        packages[profile] = set(lines)

    for profile in ('linux-core-only', 'linux-sanitize-core-only'):
        require(packages[profile] == BASIC,
                f'{profile}: must install only four Qt-independent base tools')
    for profile in ('linux-release', 'linux-debug', 'linux-sanitize', 'qml'):
        require(BASIC | DESKTOP <= packages[profile],
                f'{profile}: desktop prerequisites missing')
    require('clang-tidy' in packages['linux-analysis'],
            'analysis profile must have clang-tidy')
    require({'clazy', 'libomp-dev'} <= packages['linux-clazy'],
            'Clazy profile must have Clazy and libomp-dev')
    require(packages['policy'] == {'python3', 'reuse', 'python3-yaml'},
            'policy profile must only install its 3 required packages')
    for invalid in ('nonsense', 'linux-unapproved'):
        proc = subprocess.run(['bash', str(HELPER), invalid, '--list'],
                              capture_output=True, text=True)
        require(proc.returncode != 0,
                f'unknown dependency profile {invalid} accepted')

    shell = HELPER.read_text(encoding='utf-8')
    require('dpkg-query' in shell and 'missing+=("$package")' in shell,
            'missing-package detection cannot be disabled')
    require('if (( ${#missing[@]} > 0 ))' in shell,
            'APT update/install must be conditional on missing packages')
    require('sudo apt-get update' in shell
            and '--no-install-recommends "${missing[@]}"' in shell,
            'install must use only missing approved packages')
    require('VERSION_ID' in shell and '26.04' in shell
            and 'uname -m' in shell and 'x86_64' in shell,
            'Ubuntu 26.04 x86-64 runner gate missing')
    require('actions/cache' not in shell and 'apt-get clean' not in shell,
            'do not restore opaque caches or globally clear APT state')
    print('M1.9 CI profile check: PASS (7 build, QML, policy; core-only=4 tools)')


def check_workflow() -> None:
    workflow = read('.github/workflows/ubuntu-26-04.yml')
    require('runs-on: ubuntu-26.04' in workflow,
            'Ubuntu runner must stay pinned')
    require("bash scripts/ci/install_dependencies.sh '${{ matrix.preset }}'" in workflow,
            'matrix must install selected profile')
    require('bash scripts/ci/install_dependencies.sh qml' in workflow
            and 'bash scripts/ci/install_dependencies.sh policy' in workflow,
            'qml/policy jobs must use targeted profiles')
    require('sudo apt-get update' not in workflow and 'sudo apt-get install' not in workflow,
            'unconditional APT provisioning reintroduced in workflow')
    require('ctest --preset' in workflow and 'reuse lint' in workflow
            and 'knetsentry_qmllint' in workflow
            and 'python3 scripts/check_qml_lint.py' in workflow,
            'mandatory CI gates missing')
    for preset in PRESETS:
        require(preset in workflow, f'missing required CI preset {preset}')
    require(workflow.count('uses: actions/checkout@') == 3,
            'all three jobs must retain reviewed SHA-pinned checkout')
    require('permissions:\n  contents: read' in workflow,
            'read-only token must remain mandatory')
    require('secrets.' not in workflow and 'actions/cache' not in workflow,
            'new privileged cache or secret boundary needs separate review')
    print('M1.9 CI workflow check: PASS (9 existing jobs retained, no opaque cache)')


def check_links(doc: str) -> None:
    path = ROOT / doc
    data = path.read_text(encoding='utf-8')
    for dest in re.findall(r'(?<!!)\[[^\]]+\]\(([^)]+)\)', data):
        if dest.startswith(('http:', 'https:', 'mailto:', '#')):
            continue
        target = (path.parent / dest.split('#')[0]).resolve()
        require(target.is_relative_to(ROOT) and target.exists(),
                f'{doc}: broken/escaping local link {dest}')


def check_docs() -> None:
    docs = [
        'README.md', 'CONTRIBUTING.md', 'SECURITY.md',
        'docs/development/CONTRIBUTOR_QUICKSTART.md',
        'docs/development/CI_EFFICIENCY_M19.md',
        'docs/development/REPOSITORY_METADATA_M19.md',
        'docs/development/CI_IMPLEMENTATION_M18.md',
    ]
    for doc in docs:
        data = read(doc)
        require('SPDX-FileCopyrightText: 2026 Chris Sutton' in data
                and ('SPDX-' + 'License-Identifier:') in data,
                f'{doc}: missing licensing header')
        check_links(doc)
    quick = read('docs/development/CONTRIBUTOR_QUICKSTART.md')
    for command in ('sudo apt-get install', 'cmake --preset linux-release --fresh',
                    'cmake --build --preset linux-release',
                    'ctest --preset linux-release --output-on-failure',
                    'cmake --preset linux-sanitize --fresh',
                    'ctest --preset linux-sanitize --output-on-failure',
                    'reuse lint', 'scripts/verify_m17_suites.py',
                    'scripts/verify_m18_ci.py --format'):
        require(command in quick, f'quickstart missing command: {command}')
    from verify_m17_suites import CORE_TESTS, DESKTOP_TESTS, NONSAN_DESKTOP_TESTS
    desktop = len(CORE_TESTS | DESKTOP_TESTS | NONSAN_DESKTOP_TESTS)
    sanitizer = len(CORE_TESTS | DESKTOP_TESTS) + 1
    for required in (f'{desktop} CTest', f'{sanitizer} CTests', 'core-only', 'non-operational',
                     'security', 'private advisory'):
        require(required.lower() in quick.lower(),
                f'quickstart missing qualification/safety statement: {required}')
    readme = read('docs/README.md')
    for reference in ('CONTRIBUTOR_QUICKSTART.md', 'CI_EFFICIENCY_M19.md',
                      'REPOSITORY_METADATA_M19.md',
                      'PROJECT_STATUS.md'):
        require(reference in readme, f'Documentation index omits {reference}')
    metadata = read('docs/development/REPOSITORY_METADATA_M19.md')
    for asset in ('.github/ISSUE_TEMPLATE/', '.github/pull_request_template.md',
                  'CODEOWNERS', 'SECURITY.md', 'reuse lint'):
        require(asset in metadata, f'metadata audit missing: {asset}')
    contributing = read('CONTRIBUTING.md')
    require('PR template' in contributing and 'self-review' in contributing
            and 'reuse lint' in contributing,
            'contributing steps must retain PR and self-review requirements')
    require('not an operational SIEM' in read('SECURITY.md'),
            'security policy must not claim operational SIEM support')
    print('M1.9 contributor documentation verification: PASS (links, builds, security)')


def main() -> int:
    try:
        check_profiles()
        check_workflow()
        check_docs()
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f'M1.9 contributor verification: FAIL: {exc}')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

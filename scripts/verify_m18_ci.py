#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M1.8 offline CI structural/security and formatting hygiene checks.

Source checks are not proof that GitHub-hosted jobs executed successfully.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {
    'linux-release', 'linux-debug', 'linux-sanitize',
    'linux-clazy', 'linux-analysis', 'linux-core-only',
    'linux-sanitize-core-only',
}
SHA = '11bd71901bbe5b1630ceea73d27597364c9af683'


def require(ok: bool, msg: str) -> None:
    if not ok:
        raise ValueError(msg)


def check_workflow(path: Path) -> None:
    s = path.read_text(encoding='utf-8')
    require('runs-on: ubuntu-26.04' in s and 'ubuntu-latest' not in s,
            'CI must run explicitly on Ubuntu 26.04')
    require(re.search(r'^permissions:\s*\n\s+contents: read\s*$', s, re.M) is not None,
            'workflow token must be read-only')
    for banned in ('pull_request_target:', 'id-token: write', 'contents: write',
                   'packages: write', 'continue-on-error:', '|| true',
                   'sudo tcpdump', 'sudo nft ', 'docker run', 'podman run'):
        require(banned not in s, f'prohibited CI pattern: {banned}')
    used = re.findall(r'^\s+-?\s*uses:\s*(\S+)', s, re.M)
    require(len(used) == 3, 'expected checkout in exactly three CI jobs')
    require(all(x == f'actions/checkout@{SHA}' for x in used),
            'every external action must use the reviewed full SHA')
    require('persist-credentials: false' in s,
            'checkout must not retain repository credentials')
    require('pull_request:' in s and 'workflow_dispatch:' in s,
            'required CI triggers absent')
    for preset in EXPECTED:
        require(preset in s, f'missing CI preset: {preset}')
    for step in ('reuse lint', 'knetsentry_qmllint', 'ctest --preset',
                 'verify_m12_hardening.py', 'verify_m17_suites.py',
                 'verify_m18_ci.py', 'clang-tidy', 'clazy', 'libomp-dev'):
        require(step in s, f'missing required gate: {step}')
    require('fail-fast: false' in s, 'CI must report every matrix lane')
    require('timeout-minutes:' in s and 'cancel-in-progress: true' in s,
            'CI needs bounded runtime and cancellation')
    require('upload-artifact' not in s and 'secrets.' not in s,
            'PR jobs must not transfer artifacts or reference secrets')
    print('M1.8 CI workflow contract: PASS (source-only)')


def check_format() -> None:
    # Baseline formatting hygiene: preserve existing coding conventions without
    # rewriting all M1.1-M1.7 C++ and QML in a security-sensitive CI change.
    suffixes = {'.cpp', '.hpp', '.h', '.qml', '.cmake', '.py', '.yml', '.yaml'}
    checked = 0
    for directory in ('.github', 'apps', 'cmake', 'include', 'src', 'tests', 'scripts'):
        for p in (ROOT / directory).rglob('*'):
            if not p.is_file() or (p.suffix not in suffixes and p.name != 'CMakeLists.txt'):
                continue
            raw = p.read_bytes()
            require(b'\x00' not in raw, f'NUL byte in source: {p}')
            require(raw.endswith(b'\n'), f'missing final newline: {p}')
            require(b'\r\n' not in raw, f'CRLF source: {p}')
            for number, line in enumerate(raw.splitlines(), 1):
                require(line.rstrip(b' \t') == line,
                        f'trailing whitespace {p.relative_to(ROOT)}:{number}')
            checked += 1
    require(checked > 20, 'unexpectedly small source inventory')
    print(f'M1.8 formatting hygiene: PASS ({checked} first-party source files)')



def check_reuse_source_literals() -> None:
    """Prevent verifier fixtures from being read as extra SPDX license tags.

    REUSE scans more than the file header, including Python assertion literals.
    Actual top-of-file SPDX declarations stay plain-text and are still required.
    The verifier fixtures use Python escape sequences for the hyphen so that
    their *evaluated* strings match the original SPDX tags exactly.
    """
    marker = 'SPDX-' + 'License-Identifier:'
    checked = 0
    for script in sorted((ROOT / 'scripts').glob('*.py')):
        lines = script.read_text(encoding='utf-8').splitlines()
        require(len(lines) >= 3, f'{script.name}: short script')
        require(lines[0] == '#!/usr/bin/env python3',
                f'{script.name}: missing Python shebang')
        require(lines[1] == '# SPDX-FileCopyrightText: 2026 Chris Sutton',
                f'{script.name}: missing original copyright declaration')
        require(lines[2] == '# ' + marker + ' MIT',
                f'{script.name}: missing original MIT license declaration')
        stray = [str(i) for i, line in enumerate(lines[3:], start=4) if marker in line]
        require(not stray,
                f'{script.name}: embedded SPDX license literal on lines '
                + ', '.join(stray) + ' (escape only the in-string hyphen)')
        checked += 1
    require(checked >= 18, 'incomplete Python verifier inventory')
    print(f'M1.8 REUSE source-literal safeguard: PASS ({checked} Python files)')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--workflow', type=Path,
                        default=ROOT / '.github/workflows/ubuntu-26-04.yml')
    parser.add_argument('--format', action='store_true')
    args = parser.parse_args()
    try:
        check_workflow(args.workflow)
        check_reuse_source_literals()
        if args.format:
            check_format()
    except (OSError, ValueError) as exc:
        print(f'M1.8 CI verification: FAIL: {exc}')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

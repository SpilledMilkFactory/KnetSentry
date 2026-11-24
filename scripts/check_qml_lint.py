#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Execute the generated QML lint target and reject diagnostics even on exit 0."""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
DIAGNOSTIC = re.compile(r'^\s*(?:Warning|Error|Info):', re.MULTILINE | re.IGNORECASE)


def lint_passed(returncode: int, output: str) -> bool:
    return returncode == 0 and DIAGNOSTIC.search(ANSI.sub('', output)) is None


def main() -> int:
    command = ['cmake', '--build', '--preset', 'linux-release', '--target',
               'knetsentry_qmllint', '--parallel', '2']
    print('+ ' + ' '.join(command), flush=True)
    try:
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, check=False,
                                timeout=180)
    except subprocess.TimeoutExpired as exc:
        if exc.stdout:
            print(exc.stdout.decode(errors='replace') if isinstance(exc.stdout, bytes)
                  else exc.stdout, end='')
        print('QML static analysis: FAIL (target timed out)', file=sys.stderr)
        return 1
    except OSError as exc:
        print(f'QML static analysis: FAIL ({exc})', file=sys.stderr)
        return 1
    print(result.stdout, end='' if result.stdout.endswith('\n') else '\n', flush=True)
    if not lint_passed(result.returncode, result.stdout):
        print('QML static analysis: FAIL (target failure or lint diagnostics)', file=sys.stderr)
        return 1
    print('QML static analysis: PASS (no Warning, Error or Info diagnostics)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

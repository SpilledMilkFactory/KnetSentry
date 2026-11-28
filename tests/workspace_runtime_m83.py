#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Separate desktop processes, isolated configuration, no manager/evidence access."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from check_m25_audit_runtime import DROP, UID, GID, require
from check_m23_ipc_runtime import unprivileged


def main():
    os.umask(0o077)
    desktop = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix='ks83-', dir='/var/tmp') as name:
        root = Path(name)
        if DROP:
            os.chown(root, UID, GID)
        env = dict(os.environ, XDG_CONFIG_HOME=name)

        def run(mode):
            result = subprocess.run([str(desktop), '--self-test-workspace', mode], env=env,
                                    capture_output=True, timeout=15, check=False,
                                    preexec_fn=unprivileged if DROP else None)
            require(result.returncode == 0 and b'M8.3 default windowed geometry: PASS' in result.stdout
                    and b'M8.3 workspace rendered preferences: PASS' in result.stdout,
                    f'workspace {mode} failed: {result.returncode}')

        run('default')
        run('write')
        file = root / 'knetsentry-workspace' / 'layout.v1'
        require(file.read_bytes() == b'KSW1:65:1\n' and file.stat().st_mode & 0o777 == 0o600, 'saved schema')
        run('restore')
        file.write_bytes(b'KSW9:65:1\n')
        run('default')
        require(file.read_bytes() == b'KSW9:65:1\n', 'no automatic rewrite')
        run('write')
        run('restore')
        print('M8.3 rendered layout, separate-process restore and safe recovery: PASS')


if __name__ == '__main__':
    main()

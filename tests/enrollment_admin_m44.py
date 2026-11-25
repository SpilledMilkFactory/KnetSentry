#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Execute the actual offline administrator CLI against synthetic inputs."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ks-m44-admin-') as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        endpoint = '01' * 16
        pin = '02' * 32

        def run(*args, expected=1):
            result = subprocess.run([binary, *args], capture_output=True, timeout=5, check=False)
            if result.returncode != expected:
                raise RuntimeError(f'unexpected administrator CLI exit: {result.returncode}, expected {expected}')
            if any(marker in result.stderr for marker in (b'AddressSanitizer', b'LeakSanitizer', b'runtime error:')):
                raise RuntimeError('sanitizer diagnostic in administrator CLI')
            if endpoint.encode() in result.stdout + result.stderr or pin.encode() in result.stdout + result.stderr or ('03' * 32).encode() in result.stdout + result.stderr:
                raise RuntimeError('identity disclosed in diagnostics')

        run('approve', directory, endpoint, pin)
        run('unknown', directory, expected=2)
        run('init', directory, expected=0)
        run('init', directory)
        run('approve', directory, endpoint.upper().replace('0', 'A'), pin, expected=2)
        run('approve', directory, endpoint, 'x' * 64, expected=2)
        run('approve', directory, endpoint, pin, expected=0)
        registry = root / 'endpoints.v1'
        before = registry.read_bytes()
        if len(before) != 56 or registry.stat().st_mode & 0o777 != 0o600:
            raise RuntimeError('registry format or mode')
        run('approve', directory, endpoint, '03' * 32)
        run('approve', directory, '03' * 16, pin)
        run('approve', directory, '03' * 16, '00' * 32)
        if registry.read_bytes() != before or len(list(root.iterdir())) != 1:
            raise RuntimeError('rejected administrative operation altered registry')
        replacement = '03' * 32
        run('rotate', directory, endpoint, replacement, '04' * 32)
        run('revoke', directory, endpoint, replacement)
        if registry.read_bytes() != before:
            raise RuntimeError('stale lifecycle operation mutated registry')
        run('rotate', directory, endpoint, pin, replacement, expected=0)
        rotated = registry.read_bytes()
        if len(rotated) != 106 or rotated[5] != 2:
            raise RuntimeError('lifecycle format migration')
        run('approve', directory, '03' * 16, pin)
        run('rotate', directory, endpoint, replacement, pin)
        run('revoke', directory, endpoint, pin)
        if registry.read_bytes() != rotated:
            raise RuntimeError('retired key operation mutated registry')
        run('revoke', directory, endpoint, replacement, expected=0)
        revoked = registry.read_bytes()
        run('approve', directory, endpoint, '04' * 32)
        run('approve', directory, '03' * 16, replacement)
        run('rotate', directory, endpoint, replacement, '04' * 32)
        if registry.read_bytes() != revoked or revoked[-1] != 1 or len(list(root.iterdir())) != 1:
            raise RuntimeError('revoked identity operation mutated registry')
    print('M4.5 offline rotation/revocation CLI: PASS (synthetic identities only)')
    print('M4.4 offline administrator CLI: PASS (synthetic identities only)')


if __name__ == '__main__':
    main()

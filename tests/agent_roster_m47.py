#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Real manager and administrative registry; synthetic IDs only, no networking."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from check_m25_audit_runtime import DROP, UID, GID, private, ready, start, require
from check_m23_ipc_runtime import frame, query, unprivileged


def main():
    manager, admin, probe = (Path(arg).resolve() for arg in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix='ks47-', dir='/tmp') as name:
        base = Path(name)
        if DROP:
            os.chown(base, UID, GID)
        ipc = private(base / 'ipc')
        store = private(base / 'registry')
        audit = private(base / 'audit')
        first, second = '01' * 16, '02' * 16
        pin1, pin2, pin3 = '03' * 32, '04' * 32, '05' * 32
        prefix = b'KSIPC/1 OK 0123456789abcdef AGENTS '
        unavailable = prefix + b'UNAVAILABLE\n'
        empty = prefix + b'READY\n'

        def invoke(binary, *args):
            return subprocess.run([str(binary), *map(str, args)], capture_output=True, check=True,
                                  timeout=6, preexec_fn=unprivileged if DROP else None).stdout

        def inspect():
            return invoke(probe, ipc)

        def command(op, *args):
            invoke(admin, op, store, *args)

        unsafe = private(base / 'unsafe')
        unsafe.chmod(0o755)
        link = base / 'link'
        link.symlink_to(store, target_is_directory=True)
        for options in (['--enrollment-dir', str(store)],
                        ['--ipc-dir', str(ipc), '--enrollment-dir', str(unsafe)],
                        ['--ipc-dir', str(ipc), '--enrollment-dir', str(link)]):
            rejected = subprocess.run([str(manager), *options], capture_output=True, check=False,
                                      timeout=5, preexec_fn=unprivileged if DROP else None)
            require(rejected.returncode == 5 and not (ipc / 'manager.sock').exists(),
                    'invalid enrollment selection did not fail closed')
        proc = start(manager, ['--ipc-dir', str(ipc), '--enrollment-dir', str(store), '--audit-dir', str(audit)])
        try:
            ready(proc)
            require(inspect() == unavailable, 'absent registry not unavailable')
            command('init')
            require(inspect() == empty, 'empty registry not distinguished from unavailable')
            command('approve', first, pin1)
            command('approve', second, pin2)
            require(inspect() == empty + f'A {first}\nA {second}\n'.encode(), 'approval state mismatch')
            command('rotate', first, pin1, pin3)
            require(inspect() == empty + f'A {first}\nA {second}\n'.encode(), 'retired key appeared as revoked endpoint')
            command('revoke', second, pin2)
            expected = empty + f'A {first}\nR {second}\n'.encode()
            require(inspect() == expected, 'revocation state mismatch')
            require(all(pin.encode() not in expected for pin in (pin1, pin2, pin3)), 'pin exposed')
            require(query(ipc / 'manager.sock', frame(b'KSIPC/1 ADMIN 0123456789abcdef\n'), DROP) == b'',
                    'administrative request accepted')
            require(query(ipc / 'manager.sock', frame(b'KSIPC/1 AGENTS 0123456789abcdef extra\n'), DROP) == b'',
                    'malformed request accepted')
            require(inspect() == expected, 'denied request changed registry')
            fd = os.open(store, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                require(inspect() == unavailable, 'busy registry exposed a roster')
            finally:
                os.close(fd)
            require(inspect() == expected, 'registry did not recover after lock')
            marker = store / 'endpoints.v1.pending'
            marker.touch(mode=0o600)
            require(inspect() == unavailable, 'interrupted transaction exposed a roster')
            marker.unlink()
            (store / 'endpoints.v1').chmod(0o644)
            require(inspect() == unavailable, 'unsafe registry exposed a roster')
            (store / 'endpoints.v1').chmod(0o600)
            require(inspect() == expected, 'registry did not recover after permissions restored')
            registry = store / 'endpoints.v1'
            saved = registry.read_bytes()
            registry.write_bytes(saved + b'x')
            require(inspect() == unavailable, 'corrupt registry exposed a roster')
            registry.write_bytes(saved)
            require(inspect() == expected, 'registry did not recover after restoring fixture')
        finally:
            proc.terminate()
            proc.communicate(timeout=5)
        require(proc.returncode == 0, 'manager stop failed')
        require(inspect() == b'unavailable\n', 'stopped manager returned a roster')
        records = list(audit.iterdir())
        require(len(records) == 1, 'unexpected audit inventory')
        text = records[0].read_text()
        events = [json.loads(line)['event'] for line in text.splitlines()]
        require('agents_authorized' in events and 'administrative_denied' in events, 'missing audit evidence')
        require(all(value not in text for value in (first, second, pin1, pin2, pin3)), 'inventory logged')
        proc = start(manager, ['--ipc-dir', str(ipc)])
        try:
            ready(proc)
            require(inspect() == unavailable, 'implicit registry selection')
        finally:
            proc.terminate()
            proc.communicate(timeout=5)
        require(proc.returncode == 0, 'default manager stop failed')
    print('M4.7 real manager registry, rotation, revocation, fail-closed reads and audit: PASS')


if __name__ == '__main__':
    main()

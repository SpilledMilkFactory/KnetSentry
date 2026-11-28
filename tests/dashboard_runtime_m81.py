#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Rendered dashboard against an explicitly approved disposable M7.7 fixture."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from check_m25_audit_runtime import DROP, UID, GID, private, ready, start, require
from check_m23_ipc_runtime import unprivileged


def main():
    os.umask(0o077)
    manager, probe, desktop = (Path(arg).resolve() for arg in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix='ks81-', dir='/var/tmp') as name:
        base = Path(name)
        if DROP:
            os.chown(base, UID, GID)
        ipc, store, scheduler, alerts, audit = (private(base / part) for part in
                                               ('ipc', 'store', 'scheduler', 'alerts', 'audit'))

        def invoke(binary, *args):
            return subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=25,
                                  preexec_fn=unprivileged if DROP else None, check=False)

        require(invoke(probe, '--seed', store, scheduler, alerts).returncode == 0, 'fixture seed')
        database = store / 'events-m64.sqlite3'
        ledger = alerts / 'alerts-m76.v1'
        original, initial = database.read_bytes(), ledger.read_bytes()
        proc = start(manager, ['--ipc-dir', str(ipc), '--audit-dir', str(audit),
                               '--event-store-dir', str(store), '--alert-dir', str(alerts), '--alert-access', 'read'])
        try:
            ready(proc)
            result = invoke(desktop, '--ipc-dir', ipc, '--self-test-dashboard')
            require(result.returncode == 0 and b'M8.1 rendered stored summaries and navigation clearing: PASS' in result.stdout,
                    'rendered dashboard test')
            require(database.read_bytes() == original and ledger.read_bytes() == initial, 'read-only evidence and ledger')
        finally:
            proc.terminate()
            proc.communicate(timeout=8)
        require(proc.returncode == 0, 'manager stop')
        proc = start(manager, ['--ipc-dir', str(ipc)])
        try:
            ready(proc)
            result = invoke(desktop, '--ipc-dir', ipc, '--self-test-dashboard-denied')
            require(result.returncode == 0 and b'M8.1 rendered denied summaries: PASS' in result.stdout,
                    'default-denied dashboard test')
        finally:
            proc.terminate()
            proc.communicate(timeout=8)
        require(proc.returncode == 0, 'manager stop')
        print('M8.1 rendered dashboard, default denial and evidence invariance: PASS')


if __name__ == '__main__':
    main()

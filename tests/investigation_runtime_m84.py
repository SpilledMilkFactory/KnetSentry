#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Rendered timeline against an explicitly approved disposable M7.7 fixture."""
import json
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
    with tempfile.TemporaryDirectory(prefix='ks84-', dir='/var/tmp') as name:
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
            result = invoke(desktop, '--ipc-dir', ipc, '--self-test-timeline', 'read')
            require(result.returncode == 0 and b'M8.4 rendered timeline and evidence lifecycle: PASS' in result.stdout,
                    'rendered timeline test')
            require(b'M8.7 timeline keyboard inspection: PASS' in result.stdout, 'M8.7 keyboard inspection')
            print('M8.7 timeline keyboard inspection: PASS')
            require(b'M8.8 timeline record palette pairing: PASS' in result.stdout, 'M8.8 record palette')
            print('M8.8 timeline record palette pairing: PASS')
            require(database.read_bytes() == original and ledger.read_bytes() == initial, 'read-only evidence and ledger')
        finally:
            proc.terminate()
            proc.communicate(timeout=8)
        require(proc.returncode == 0, 'manager stop')
        records = [json.loads(line) for line in (audit / 'service-audit.jsonl').read_text().splitlines()]
        require(sum(row['event'] == 'events_authorized' for row in records) == 1 and
                sum(row['event'] == 'alerts_authorized' for row in records) == 2, 'one event, one alert page, one evidence request')
        proc = start(manager, ['--ipc-dir', str(ipc)])
        try:
            ready(proc)
            result = invoke(desktop, '--ipc-dir', ipc, '--self-test-timeline', 'denied')
            require(result.returncode == 0 and b'M8.4 rendered timeline and evidence lifecycle: PASS' in result.stdout,
                    'default-denied timeline test')
        finally:
            proc.terminate()
            proc.communicate(timeout=8)
        require(proc.returncode == 0, 'manager stop')
        print('M8.4 rendered timeline, denial, evidence invariance and audit: PASS')


if __name__ == '__main__':
    main()

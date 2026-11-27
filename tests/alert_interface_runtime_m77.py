#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Actual manager and optional rendered desktop against disposable persistent alerts."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from check_m25_audit_runtime import DROP, UID, GID, private, ready, start, require
from check_m23_ipc_runtime import frame, query, unprivileged

ID = b'0123456789abcdef'
LIST = b'KSIPC/1 ALERTS ' + ID + b' L 0 0 0 0 0 0 -\n'


def main():
    os.umask(0o077)
    manager, probe = (Path(arg).resolve() for arg in sys.argv[1:3])
    desktop = Path(sys.argv[3]).resolve() if len(sys.argv) == 4 else None
    with tempfile.TemporaryDirectory(prefix='ks77-', dir='/var/tmp') as name:
        base = Path(name)
        if DROP:
            os.chown(base, UID, GID)
        ipc, store, scheduler, alerts = (private(base / part) for part in ('ipc', 'store', 'scheduler', 'alerts'))
        def invoke(binary, *args):
            return subprocess.run([str(binary), *map(str,args)], capture_output=True, timeout=25,
                                  preexec_fn=unprivileged if DROP else None, check=False)
        require(invoke(probe, '--seed', store, scheduler, alerts).returncode == 0, 'seed failed')
        require(invoke(probe, '--seed', store, scheduler, alerts).returncode != 0, 'fixture overwrite')
        original = (store / 'events-m64.sqlite3').read_bytes()
        ledger = alerts / 'alerts-m76.v1'
        initial = ledger.read_bytes()
        def exchange(payload):
            reply = query(ipc / 'manager.sock', frame(payload), DROP)
            if not reply:
                return b''
            require(len(reply) >= 4 and int.from_bytes(reply[:4], 'big') == len(reply)-4 <= 4096, 'frame')
            return reply[4:]
        def launch(access, audit):
            return start(manager, ['--ipc-dir', str(ipc), '--audit-dir', str(audit), '--event-store-dir', str(store),
                                   '--alert-dir', str(alerts), '--alert-access', access])
        def stop(proc):
            proc.terminate()
            proc.communicate(timeout=8)
            require(proc.returncode == 0, 'manager stop')
        inactive = start(manager, ['--ipc-dir', str(ipc)])
        try:
            ready(inactive)
            require(exchange(LIST) == b'', 'default access')
        finally:
            stop(inactive)
        proc = launch('read', private(base/'audit-read'))
        try:
            ready(proc)
            first = exchange(LIST).splitlines()
            require(len(first) == 9 and first[0].split()[3] == b'OK' and first[0].endswith(b' 1 0'), 'read page')
            session = first[0].split()[4]
            ack = b'KSIPC/1 ALERTS ' + ID + b' A 0 0 1 2 1 0 ' + session + b'\n'
            require(exchange(ack) == b'' and ledger.read_bytes() == initial, 'read only mutation')
            if DROP:
                require(query(ipc/'manager.sock', frame(LIST), False) == b'', 'foreign peer')
        finally:
            stop(proc)
        audit = private(base/'audit-ack')
        proc = launch('ack', audit)
        try:
            ready(proc)
            require(invoke(probe, '--client', ipc).returncode == 0, 'native client')
            require(exchange(ack).split()[3] == b'STALE', 'old session')
            first = exchange(LIST).splitlines()
            session = first[0].split()[4]
            ack = b'KSIPC/1 ALERTS ' + ID + b' A 0 0 1 2 1 0 ' + session + b'\n'
            evidence = b'KSIPC/1 ALERTS ' + ID + b' E 0 0 1 2 1 1 ' + session + b'\n'
            require(exchange(evidence).splitlines()[1].startswith(b'1 '), 'linked evidence')
            require(exchange(evidence.replace(b' E 0 0 1 2 1 1 ', b' E 0 0 1 2 1 3 ')).split()[3] == b'DENIED', 'unlinked evidence')
            require(exchange(ack + b'extra') == b'', 'trailing request')
            require(exchange(ack).split()[3] == b'OK' and exchange(ack).split()[3] == b'STALE', 'ack or stale revision')
            require(exchange(LIST).splitlines()[1].split()[2:5] == [b'2', b'3', b'1'], 'persisted revision/status')
            if desktop:
                result = invoke(desktop, '--ipc-dir', ipc, '--self-test-alerts')
                require(result.returncode == 0 and b'M7.7 rendered alert interface: PASS' in result.stdout, 'rendered alert test')
            require((store/'events-m64.sqlite3').read_bytes() == original, 'evidence database changed')
        finally:
            stop(proc)
        entries = [json.loads(line) for line in (audit/'service-audit.jsonl').read_text().splitlines()]
        require(any(row['event'] == 'alert_acknowledge_authorized' for row in entries) and any(row['event'] == 'alert_acknowledged' for row in entries), 'audit')
        require('ssh.service' not in (audit/'service-audit.jsonl').read_text(), 'audit telemetry leak')
        proc = launch('read', private(base/'audit-restart'))
        try:
            ready(proc)
            require(exchange(LIST).splitlines()[1].split()[2:5] == [b'2', b'3', b'1'], 'restart persistence')
        finally:
            stop(proc)
        print('M7.7 manager IPC, default denial, read-only policy, audit, revision and restart: PASS')


if __name__ == '__main__':
    main()

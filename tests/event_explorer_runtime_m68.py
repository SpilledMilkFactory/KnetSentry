#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Actual manager, persistent SQLite fixture, bounded IPC and optional rendered GUI."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from check_m25_audit_runtime import DROP, UID, GID, private, ready, start, require
from check_m23_ipc_runtime import frame, query, unprivileged

REQUEST = b'KSIPC/1 EVENTS 0123456789abcdef A - - - 0 0 -\n'


def main():
    os.umask(0o077)
    manager, probe = (Path(arg).resolve() for arg in sys.argv[1:3])
    desktop = Path(sys.argv[3]).resolve() if len(sys.argv) == 4 else None
    with tempfile.TemporaryDirectory(prefix='ks68-', dir='/var/tmp') as name:
        base = Path(name)
        if DROP:
            os.chown(base, UID, GID)
        ipc = private(base / 'ipc')
        store = private(base / 'store')
        audit = private(base / 'audit')
        missing = private(base / 'missing')
        rejected_audit = private(base / 'reject-audit')
        db = store / 'events-m64.sqlite3'

        def invoke(binary, *args):
            return subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=18,
                                  preexec_fn=unprivileged if DROP else None, check=False)

        def exchange(payload):
            reply = query(ipc / 'manager.sock', frame(payload), DROP)
            if not reply:
                return b''
            require(len(reply) >= 4 and int.from_bytes(reply[:4], 'big') == len(reply) - 4 <= 4096,
                    'invalid reply frame')
            return reply[4:]

        def launch(directory, audit_directory):
            return start(manager, ['--ipc-dir', str(ipc), '--audit-dir', str(audit_directory),
                                   '--event-store-dir', str(directory)])

        def stop(proc):
            proc.terminate()
            proc.communicate(timeout=8)
            require(proc.returncode == 0, 'manager failed to stop')

        require(invoke(probe, '--seed', store).returncode == 0, 'fixture seed failed')
        require(invoke(probe, '--seed', store).returncode != 0, 'fixture overwrote existing records')
        require(invoke(manager, '--ipc-dir', ipc, '--event-store-dir', store).returncode != 0,
                'unaudited inspection enabled')
        require(invoke(manager, '--ipc-dir', ipc, '--audit-dir', rejected_audit, '--event-store-dir', missing).returncode != 0,
                'missing store activation accepted')
        require(not list(missing.iterdir()) and not (ipc / 'manager.sock').exists(), 'missing store created')
        inactive = start(manager, ['--ipc-dir', str(ipc)])
        try:
            ready(inactive)
            require(exchange(REQUEST) == b'', 'non-opted-in manager exposed an event page')
        finally:
            stop(inactive)
        original = db.read_bytes()
        proc = launch(store, audit)
        try:
            ready(proc)
            require(invoke(probe, '--client', ipc).returncode == 0, 'native client contract failed')
            if DROP:
                require(query(ipc / 'manager.sock', frame(REQUEST), False) == b'', 'foreign UID accepted')
            page = exchange(REQUEST).splitlines()
            require(len(page) == 9 and page[0].split()[3] == b'OK' and page[0].endswith(b' 1'), 'page bound')
            require([int(row.split()[0]) for row in page[1:]] == list(range(1, 9)), 'wrong page IDs')
            session, revision = page[0].split()[4:6]
            continuation = b'KSIPC/1 EVENTS 0123456789abcdef A - - - 8 ' + revision + b' ' + session + b'\n'
            require(exchange(REQUEST.replace(b' - - - ', b' - - *.service ')) == b'', 'wildcard accepted')
            require(exchange(REQUEST + b'extra') == b'', 'trailing request accepted')
            require(exchange(b'KSIPC/1 ADMIN 0123456789abcdef\n') == b'', 'admin accepted')
            require(exchange(REQUEST.replace(b' A ', b' X ')) == b'', 'unknown sort accepted')
            require(exchange(REQUEST.replace(b' A ', b' D ')).splitlines()[1].startswith(b'20 '), 'descending order')
            if desktop:
                def query_count():
                    return sum(json.loads(line)['event'] == 'events_authorized'
                               for line in (audit / 'service-audit.jsonl').read_text().splitlines())
                before = query_count()
                result = invoke(desktop, '--ipc-dir', ipc, '--self-test-events')
                require(result.returncode == 0 and b'M6.8 rendered event explorer: PASS' in result.stdout,
                        'rendered explorer contract failed')
                require(b'M8.6 rendered event presets, saved views and cross-view clearing: PASS' in result.stdout, 'M8.6 rendered controls')
                require(query_count() - before == 4, 'M8.6 unexpected authorized query count')
                print('M8.6 rendered event presets, saved views and cross-view clearing: PASS')
            # Existing developer store must not be mutated by these searches.
            require(db.read_bytes() == original, 'query altered database bytes')
        finally:
            stop(proc)
        records = [json.loads(line) for line in (audit / 'service-audit.jsonl').read_text().splitlines()]
        require(any(row['event'] == 'events_authorized' for row in records), 'missing authorization audit')
        require('ssh.service' not in (audit / 'service-audit.jsonl').read_text(), 'source leaked into audit')
        # Restart retains records but invalidates old instance continuation.
        proc = launch(store, private(base / 'audit2'))
        try:
            ready(proc)
            require(exchange(continuation).split()[3] == b'STALE', 'old session accepted after restart')
            require(exchange(REQUEST).splitlines()[1].startswith(b'1 '), 'restart lost stored evidence')
            with sqlite3.connect(db) as connection:
                connection.execute("UPDATE evidence_integrity SET sha256=? WHERE id=20", ('0' * 64,))
            corrupt = exchange(REQUEST.replace(b' - - - ', b' - - fixture.service ')).splitlines()
            require(len(corrupt) == 1 and corrupt[0].split()[3] == b'INTEGRITY', 'filtered corruption exposed a page')
        finally:
            stop(proc)
        print('M6.8 real SQLite manager, native IPC, opt-in, audit, restart and integrity refusal: PASS')
        if desktop:
            print('M6.8 rendered event explorer: PASS')


if __name__ == '__main__':
    main()

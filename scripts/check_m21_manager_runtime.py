#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Run a real unprivileged knetsentryd and verify SIGTERM/SIGINT lifecycle.

Synthetic process test: no network requests, credentials, filesystem state,
or operational SIEM activity. A successful source check is not runtime proof.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

EXPECTED = ['manager_starting', 'manager_ready', 'manager_stopping', 'manager_stopped']


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def launch(binary: Path, sig: signal.Signals) -> None:
    # CI runs unprivileged. When validation runs in a root-owned isolated
    # container, explicitly drop to nobody in the child before exec; don't
    # relax the production root prohibition for tests.
    drop = os.geteuid() == 0
    def child_identity() -> None:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)

    proc = subprocess.Popen(
        [str(binary)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, bufsize=0, preexec_fn=child_identity if drop else None)
    try:
        assert proc.stderr is not None
        assert proc.stdout is not None
        data = bytearray()
        deadline = time.monotonic() + 12
        while b'"event":"manager_ready"' not in data:
            remaining = deadline - time.monotonic()
            require(remaining > 0, f'{sig.name}: manager did not reach ready')
            ready, _, _ = select.select([proc.stderr], [], [], remaining)
            require(bool(ready), f'{sig.name}: timeout waiting for readiness')
            chunk = os.read(proc.stderr.fileno(), 4096)
            require(bool(chunk), f'{sig.name}: manager exited before ready: {data!r}')
            data.extend(chunk)
            require(len(data) <= 4096, f'{sig.name}: excessive startup diagnostics')
        proc.send_signal(sig)
        out, err = proc.communicate(timeout=12)
        data.extend(err)
        require(proc.returncode == 0, f'{sig.name}: shutdown exit {proc.returncode}')
        require(out == b'', f'{sig.name}: unexpected stdout')
        require(len(data) <= 4096, f'{sig.name}: excessive diagnostic output')
        records = [json.loads(line) for line in data.decode('utf-8').splitlines()]
        require([record['event'] for record in records] == EXPECTED,
                f'{sig.name}: incorrect lifecycle sequence')
        for index, record in enumerate(records, 1):
            require(set(record) == {'schema', 'time_unix_ms', 'sequence',
                'level', 'component', 'event', 'outcome', 'count', 'private_detail'},
                f'{sig.name}: unexpected JSON schema')
            require(record['schema'] == 1 and record['sequence'] == index,
                    f'{sig.name}: invalid schema or sequence')
            require(record['component'] == 'manager' and record['private_detail'] is None,
                    f'{sig.name}: wrong component or private content')
            require(record['count'] is None and record['level'] == 'info',
                    f'{sig.name}: unexpected metadata')
            require(record['outcome'] == ('started' if index in (1, 3) else 'success'),
                    f'{sig.name}: unexpected lifecycle outcome')
            require(isinstance(record['time_unix_ms'], int),
                    f'{sig.name}: invalid timestamp')
        print(f'M2.1 real daemon {sig.name}: PASS (4 ordered, bounded JSONL records)')
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    try:
        binary = args.binary.resolve()
        require(binary.is_file() and os.access(binary, os.X_OK), 'missing built daemon')
        version = subprocess.run([str(binary), '--version'], capture_output=True,
                                 text=True, timeout=5, check=False)
        require(version.returncode == 0 and 'KnetSentry manager ' in version.stdout,
                'headless --version failed')
        help_text = subprocess.run([str(binary), '--help'], capture_output=True,
                                   text=True, timeout=5, check=False)
        require(help_text.returncode == 0 and 'SIGTERM' in help_text.stdout,
                'headless --help failed')
        for bad_arg in ('--daemonize', '--listen', '--config', '--self-test-qml'):
            rejected = subprocess.run([str(binary), bad_arg], capture_output=True,
                                      text=True, timeout=5, check=False)
            require(rejected.returncode == 2, f'unapproved option {bad_arg} accepted')
        if os.geteuid() == 0:
            refused = subprocess.run([str(binary)], capture_output=True,
                                     text=True, timeout=5, check=False)
            require(refused.returncode == 3 and 'root execution prohibited' in refused.stderr,
                    'running daemon as root was not denied')
        launch(binary, signal.SIGTERM)
        launch(binary, signal.SIGINT)
        print('M2.1 daemon runtime verification: PASS')
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f'M2.1 daemon runtime verification: FAIL: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

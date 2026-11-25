#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Exercise live embedded QML state through a real daemon stop and restart."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time

from check_m25_audit_runtime import DROP, UID, GID, owner_file, private, ready, start, require
from check_m22_config_runtime import VALID
from check_m23_ipc_runtime import frame, query, unprivileged


def wait_marker(proc: subprocess.Popen, marker: bytes, data: bytes) -> bytes:
    deadline = time.monotonic() + 6
    while marker not in data:
        require(time.monotonic() < deadline, 'GUI state transition timeout')
        assert proc.stdout is not None
        if select.select([proc.stdout], [], [], 0.2)[0]:
            part = os.read(proc.stdout.fileno(), 1024)
            require(bool(part), 'GUI exited before state transition')
            data += part
            require(len(data) < 8192, 'unexpected GUI output')
    return data


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate(timeout=3)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--desktop', type=Path, required=True)
    parser.add_argument('--manager', type=Path, required=True)
    parser.add_argument('--admin', type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='ks26-gui-', dir='/tmp') as name:
        base = Path(name)
        if DROP:
            os.chown(base, UID, GID)
        ipc = private(base / 'ipc')
        runtime = private(base / 'runtime')
        env = os.environ.copy()
        env.update(QT_QPA_PLATFORM='offscreen', QT_QUICK_BACKEND='software',
                   QT_QUICK_CONTROLS_STYLE='Basic', XDG_RUNTIME_DIR=str(runtime),
                   LC_ALL='C')
        store = private(base / 'registry')
        for command in (['init'], ['approve', '01' * 16, '03' * 32],
                        ['approve', '02' * 16, '04' * 32], ['revoke', '02' * 16, '04' * 32]):
            subprocess.run([str(args.admin.resolve()), command[0], str(store), *command[1:]],
                           capture_output=True, check=True, timeout=5,
                           preexec_fn=unprivileged if DROP else None)
        manager = start(args.manager.resolve(), ['--ipc-dir', str(ipc), '--enrollment-dir', str(store)])
        gui = None
        try:
            ready(manager)
            require(query(ipc / 'manager.sock', frame(b'KSIPC/1 ADMIN 0123456789abcdef\n'), DROP) == b'',
                    'synthetic administrative request was not denied')
            gui = subprocess.Popen([str(args.desktop.resolve()), '--ipc-dir', str(ipc),
                                    '--self-test-health'], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env,
                                   preexec_fn=unprivileged if DROP else None)
            output = wait_marker(gui, b'M2.6 GUI connected', b'')
            stop(manager)
            require(manager.returncode == 0, 'manager shutdown failure')
            output = wait_marker(gui, b'M2.6 GUI disconnected', output)
            config = base / 'manager.conf'
            owner_file(config, VALID)
            manager = start(args.manager.resolve(), ['--ipc-dir', str(ipc), '--config', str(config)])
            ready(manager)
            output = wait_marker(gui, b'M2.6 GUI reconnected: PASS', output)
            require(b'M3.8 scope connected, denied IPC, disconnected and reconnected: PASS' in output,
                    'missing real Settings scope transition evidence')
            require(b'M4.7 GUI approved and revoked registry identities: PASS' in output and
                    b'M4.7 GUI registry cleared on disconnect and unconfigured restart: PASS' in output,
                    'missing rendered agent roster evidence')
            _, errors = gui.communicate(timeout=5)
            require(gui.returncode == 0, 'GUI health verification failed')
            require(b'ReferenceError' not in errors and b'TypeError' not in errors,
                    'QML binding failure')
        finally:
            if gui is not None:
                stop(gui)
            stop(manager)
    print('M2.6 actual GUI health, disconnection and reconnection: PASS')
    print('M3.8 actual Settings scope and local IPC counter separation: PASS')
    print('M4.7 actual Assets roster, disconnection and unconfigured restart: PASS')


if __name__ == '__main__':
    main()

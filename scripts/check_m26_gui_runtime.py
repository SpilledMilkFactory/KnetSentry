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

from check_m25_audit_runtime import DROP, UID, GID, private, ready, start, require
from check_m23_ipc_runtime import unprivileged


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
        manager = start(args.manager.resolve(), ['--ipc-dir', str(ipc)])
        gui = None
        try:
            ready(manager)
            gui = subprocess.Popen([str(args.desktop.resolve()), '--ipc-dir', str(ipc),
                                    '--self-test-health'], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env,
                                   preexec_fn=unprivileged if DROP else None)
            output = wait_marker(gui, b'M2.6 GUI connected', b'')
            stop(manager)
            require(manager.returncode == 0, 'manager shutdown failure')
            output = wait_marker(gui, b'M2.6 GUI disconnected', output)
            manager = start(args.manager.resolve(), ['--ipc-dir', str(ipc)])
            ready(manager)
            wait_marker(gui, b'M2.6 GUI reconnected: PASS', output)
            _, errors = gui.communicate(timeout=5)
            require(gui.returncode == 0, 'GUI health verification failed')
            require(b'ReferenceError' not in errors and b'TypeError' not in errors,
                    'QML binding failure')
        finally:
            if gui is not None:
                stop(gui)
            stop(manager)
    print('M2.6 actual GUI health, disconnection and reconnection: PASS')


if __name__ == '__main__':
    main()

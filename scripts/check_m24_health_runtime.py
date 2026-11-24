#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Exercise live health, resource units, counters and the existing peer gate."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

from check_m23_ipc_runtime import frame, query, require, unprivileged

ID = b'0123456789abcdef'
HEALTH = b'KSIPC/1 HEALTH ' + ID + b'\n'
STATUS = b'KSIPC/1 STATUS ' + ID + b'\n'


def get_health(path: Path, drop: bool, config: bytes) -> tuple[int, ...]:
    reply = query(path, frame(HEALTH), drop)
    require(4 < len(reply) <= 260, 'health response size outside limit')
    require(struct.unpack('!I', reply[:4])[0] == len(reply) - 4, 'incorrect framing')
    require(reply.endswith(b'\n'), 'missing health terminator')
    fields = reply[4:-1].split(b' ')
    require(len(fields) == 14, 'unexpected health field count')
    require(fields[:5] == [b'KSIPC/1', b'OK', ID, b'HEALTH', b'RUNNING'],
            'unexpected health state or correlation ID')
    require(fields[8:11] == [config, b'IPC_READY', b'MONITORING_UNAVAILABLE'],
            'component status misrepresented')
    numbers = fields[5:8] + fields[11:14]
    require(all(n.isdigit() and len(n) <= 20 and int(n) <= 2**64 - 1
                for n in numbers), 'resource sample unavailable or invalid numeric field')
    return tuple(int(n) for n in numbers)


def exercise(binary: Path, explicit: bool) -> None:
    drop = os.geteuid() == 0
    with tempfile.TemporaryDirectory(prefix='ks-m24-') as root:
        directory = Path(root)
        config = directory / 'manager.conf'
        if explicit:
            config.write_bytes((Path(__file__).resolve().parent.parent /
                                'examples/manager-v1.conf').read_bytes())
            config.chmod(0o600)
        if drop:
            os.chown(directory, 65534, 65534)
            if explicit:
                os.chown(config, 65534, 65534)
        args = [str(binary)] + (['--config', str(config)] if explicit else [])
        args += ['--ipc-dir', str(directory)]
        started = time.monotonic()
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, preexec_fn=unprivileged if drop else None)
        diagnostics = b''
        path = directory / 'manager.sock'
        mode = b'CONFIG_VALIDATED' if explicit else b'CONFIG_DEFAULT'
        try:
            while b'"event":"manager_ready"' not in diagnostics:
                require(time.monotonic() - started < 6, 'manager readiness timeout')
                assert proc.stderr is not None
                readable, _, _ = select.select([proc.stderr], [], [], 0.25)
                if readable:
                    data = os.read(proc.stderr.fileno(), 1024)
                    require(bool(data), 'manager exited before readiness')
                    diagnostics += data
            first = get_health(path, drop, mode)
            require(first[0] <= (time.monotonic() - started) * 1000 + 100,
                    'uptime exceeds independently measured elapsed time')
            require(first[2] > 0 and first[3:] == (0, 0, 0), 'unexpected initial health')
            require(query(path, frame(STATUS), drop) ==
                    frame(b'KSIPC/1 OK ' + ID + b' LIFECYCLE_ONLY\n'), 'STATUS regression')
            time.sleep(0.12)
            for invalid in (b'KSIPC/2 HEALTH ' + ID + b'\n',
                            b'KSIPC/1 HEALTH 0123456789abcdeG\n',
                            HEALTH + b'EXTRA', b'KSIPC/1 ADMIN ' + ID + b'\n',
                            b'X' * 65, b''):
                require(query(path, frame(invalid), drop) == b'', 'invalid request disclosed data')
            # An incomplete header is a transport error, not a valid request.
            require(query(path, b'\x00\x00', drop) == b'', 'partial header disclosed data')
            # Real different-UID peer; the parent root can traverse filesystem DAC.
            if drop:
                with socket.socket(socket.AF_UNIX) as peer:
                    peer.settimeout(2)
                    peer.connect(str(path))
                    try:
                        peer.sendall(frame(HEALTH))
                        denied = peer.recv(512)
                    except (ConnectionResetError, BrokenPipeError):
                        denied = b''
                    require(denied == b'', 'different-UID peer obtained health')
            second = get_health(path, drop, mode)
            require(second[0] >= first[0] + 100, 'uptime failed to advance')
            require(second[1] >= first[1] and second[2] >= first[2], 'resource totals regressed')
            require(second[3:] == (6 + int(drop), 1, 0), 'incorrect operational error counters')
            third = get_health(path, drop, mode)
            require(third[3:] == second[3:], 'valid health query altered error counters')
            proc.send_signal(signal.SIGTERM)
            _, err = proc.communicate(timeout=5)
            diagnostics += err
            require(proc.returncode == 0 and not path.exists(), 'shutdown/cleanup regression')
            require([json.loads(line)['event'] for line in diagnostics.splitlines()] ==
                    ['manager_starting', 'manager_ready', 'manager_stopping', 'manager_stopped'],
                    'diagnostic lifecycle regression')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=4)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    args = parser.parse_args()
    try:
        for explicit in (False, True):
            exercise(args.binary.resolve(), explicit)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f'M2.4 health runtime: FAIL: {exc}', file=sys.stderr)
        return 1
    print('M2.4 cross-UID live health: ' + ('PASS' if os.geteuid() == 0 else
          'NOT_APPLICABLE (no privilege to switch user)'))
    print('M2.4 live health: PASS (uptime, resources, components, counters, framing, cleanup)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Real manager exchange and hostile synthetic local response fixtures."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

from check_m25_audit_runtime import DROP, UID, GID, private, ready, start, require
from check_m23_ipc_runtime import unprivileged

ID = b'0123456789abcdef'
PAYLOAD = (b'KSIPC/1 OK ' + ID + b' HEALTH RUNNING 42 0 123 '
           b'CONFIG_DEFAULT IPC_READY MONITORING_UNAVAILABLE 0 0 0\n')


def frame(payload: bytes) -> bytes:
    return struct.pack('!I', len(payload)) + payload


def run(probe: Path, directory: Path, drop: bool = False) -> str:
    result = subprocess.run([str(probe), str(directory)], capture_output=True, text=True,
                            timeout=5, check=True, preexec_fn=unprivileged if drop else None)
    return result.stdout.strip()


def fake(probe: Path, directory: Path, chunks: list[bytes], expected: str,
         stall: bool = False) -> None:
    path = directory / 'manager.sock'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        path.chmod(0o600)
        server.listen(1)
        server.settimeout(4)
        with subprocess.Popen([str(probe), str(directory)], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True) as proc:
            try:
                client, _ = server.accept()
                with client:
                    client.settimeout(3)
                    data = bytearray()
                    while len(data) < 36:
                        chunk = client.recv(64)
                        require(bool(chunk), 'client closed before request')
                        data.extend(chunk)
                    require(bytes(data) == frame(b'KSIPC/1 HEALTH ' + ID + b'\n'),
                            'client request changed')
                    for chunk in chunks:
                        client.sendall(chunk)
                        time.sleep(0.02)
                    if stall:
                        time.sleep(2.2)
                output, _ = proc.communicate(timeout=4)
                require(proc.returncode == 0 and output.strip().startswith(expected),
                        'incorrect synthetic response classification')
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=3)
    path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--manager', type=Path, required=True)
    args = parser.parse_args()
    probe, manager = args.probe.resolve(), args.manager.resolve()
    with tempfile.TemporaryDirectory(prefix='ks26-', dir='/tmp') as name:
        base = Path(name)
        if DROP:
            os.chown(base, UID, GID)
        ipc = private(base / 'ipc')
        require(run(probe, ipc, DROP) == 'unavailable', 'absent socket')
        proc = start(manager, ['--ipc-dir', str(ipc)])
        try:
            ready(proc)
            require(run(probe, ipc, DROP).startswith('available '), 'real manager query')
        finally:
            if proc.poll() is None:
                proc.terminate()
            proc.communicate(timeout=5)
        require(proc.returncode == 0 and run(probe, ipc, DROP) == 'unavailable', 'shutdown')
        if DROP:
            # Let the client reach a socket owned by its own UID while the
            # listening process has a different kernel-reported identity.
            # The client must reject before disclosing even its read-only request.
            path = ipc / 'manager.sock'
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(path))
                os.chown(path, UID, GID)
                path.chmod(0o600)
                server.listen(1)
                server.settimeout(3)
                require(run(probe, ipc, True) == 'unavailable', 'wrong server identity accepted')
                client, _ = server.accept()
                with client:
                    client.settimeout(2)
                    require(client.recv(64) == b'', 'request sent to wrong server identity')
            path.unlink()
            print('M2.6 cross-UID server identity rejection: PASS')
        else:
            print('M2.6 cross-UID server identity rejection: NOT_APPLICABLE (unprivileged harness)')
        # Synthetic peers run with the current harness identity (no privilege elevation).
        fixtures = base / 'fixtures'
        fixtures.mkdir(mode=0o700)
        wire = frame(PAYLOAD)
        fake(probe, fixtures, [wire[:2], wire[2:10], wire[10:]], 'available 42 0')
        fake(probe, fixtures, [wire[:-1]], 'invalid')
        fake(probe, fixtures, [wire + b'x'], 'invalid')
        fake(probe, fixtures, [struct.pack('!I', 257)], 'invalid')
        fake(probe, fixtures, [frame(PAYLOAD.replace(ID, b'fedcba9876543210'))], 'invalid')
        fake(probe, fixtures, [wire], 'unavailable', stall=True)
        path = fixtures / 'manager.sock'
        path.symlink_to('/dev/null')
        require(run(probe, fixtures) == 'unavailable', 'unsafe socket path')
        path.unlink()
        fixtures.chmod(0o755)
        require(run(probe, fixtures) == 'unavailable', 'unsafe directory')
    print('M2.6 native health client: PASS (real manager, framing, timeout, disconnect)')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M2.3 real AF_UNIX peer-auth, bounded-wire, shutdown and fail-closed tests."""
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


def require(value: bool, description: str) -> None:
    if not value:
        raise ValueError(description)


def unprivileged() -> None:
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)


def frame(payload: bytes) -> bytes:
    return struct.pack('!I', len(payload)) + payload


def query(sock_path: Path, packet: bytes, drop: bool, partial: bool = False) -> bytes:
    # When a root CI process starts the daemon as nobody, run an authenticated
    # client as nobody as well; untrusted request bytes never decide identity.
    if drop:
        script = """import socket,sys
s=socket.socket(socket.AF_UNIX)
s.settimeout(2)
s.connect(sys.argv[1])
s.sendall(bytes.fromhex(sys.argv[2]))
reply = bytearray()
try:
    while True:
        chunk = s.recv(512)
        if not chunk:
            break
        reply.extend(chunk)
        if len(reply) >= 4 and len(reply) >= 4 + int.from_bytes(reply[:4], 'big'):
            break
except ConnectionResetError:
    pass
print(bytes(reply).hex())
"""
        result = subprocess.run([sys.executable, '-c', script, str(sock_path), packet.hex()],
                                capture_output=True, text=True, timeout=4, check=False,
                                preexec_fn=unprivileged)
        require(result.returncode == 0, f'authenticated client failed: {result.stderr[:120]}')
        return bytes.fromhex(result.stdout.strip())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(sock_path))
        client.sendall(packet if not partial else packet[:2])
        if partial:
            return b''
        reply = bytearray()
        try:
            while True:
                chunk = client.recv(512)
                if not chunk:
                    break
                reply.extend(chunk)
                if len(reply) >= 4 and len(reply) >= 4 + int.from_bytes(reply[:4], 'big'):
                    break
        except ConnectionResetError:
            pass
        return bytes(reply)


def receive_response(sock_path: Path, payload: bytes, drop: bool) -> bytes:
    reply = query(sock_path, frame(payload), drop)
    if len(reply) >= 4:
        length = struct.unpack('!I', reply[:4])[0]
        require(length <= 64, 'response exceeds limit')
        require(len(reply[4:]) == length, 'response frame truncated')
        return reply[4:]
    return reply


def run(binary: Path) -> None:
    drop = os.geteuid() == 0
    with tempfile.TemporaryDirectory(prefix='knetsentry-m23-') as root:
        directory = Path(root) / 'private'
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
        if drop:
            os.chown(Path(root), 65534, 65534)
            os.chown(directory, 65534, 65534)
        path = directory / 'manager.sock'
        def command(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run([str(binary), *args], capture_output=True, text=True,
                check=False, timeout=6, preexec_fn=unprivileged if drop else None)

        bad = Path(root) / 'unsafe'
        bad.mkdir(mode=0o755)
        if drop: os.chown(bad, 65534, 65534)
        require(command('--ipc-dir', str(bad)).returncode == 5,
                'world-readable directory accepted')
        require(not (bad / 'manager.sock').exists(), 'unsafe directory created socket')
        require(command('--ipc-dir', str(directory / 'absent')).returncode == 5,
                'missing IPC directory accepted')
        other = directory / 'another.sock'
        other.symlink_to('/tmp/fake-knetsentry-socket')
        # A stale socket path or attacker-selected symlink cannot be unlinked.
        path.symlink_to(other)
        require(command('--ipc-dir', str(directory)).returncode == 5,
                'preexisting socket path accepted')
        require(path.is_symlink(), 'existing symlink was removed')
        path.unlink()

        proc = subprocess.Popen([str(binary), '--ipc-dir', str(directory)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=unprivileged if drop else None)
        diagnostics = b''
        try:
            started = time.monotonic()
            while b'"event":"manager_ready"' not in diagnostics:
                require(time.monotonic() - started < 6, 'IPC daemon never became ready')
                assert proc.stderr is not None
                readable, _, _ = select.select([proc.stderr], [], [], 0.25)
                if readable:
                    data = os.read(proc.stderr.fileno(), 1024)
                    require(bool(data), 'manager exited before ready')
                    diagnostics += data
            require(path.is_socket(), 'AF_UNIX socket not created')
            require((path.stat().st_mode & 0o777) == 0o600, 'socket mode must be 0600')
            identifier = b'0123456789abcdef'
            good = receive_response(path, b'KSIPC/1 STATUS ' + identifier + b'\n', drop)
            require(good == b'KSIPC/1 OK ' + identifier + b' LIFECYCLE_ONLY\n',
                    'authorized status response failed')
            # Unknown versions/operations, bogus IDs, malformed lengths and
            # excessive messages must be denied, with no data returned.
            bad_payloads = [b'KSIPC/2 STATUS ' + identifier + b'\n',
                            b'KSIPC/1 RESTART ' + identifier + b'\n',
                            b'KSIPC/1 STATUS 0123456789abcdeg\n',
                            b'KSIPC/1 STATUS ' + identifier + b'\nTRAILING', b'',
                            b'KSIPC/1 ADMIN ' + identifier + b'\n']
            for rejected in bad_payloads:
                require(receive_response(path, rejected, drop) == b'',
                        f'malformed/unauthorized command accepted: {rejected!r}')
            require(query(path, struct.pack('!I', 100000), drop) == b'',
                    'oversized advertised frame accepted')
            # Bounded slow-client wait must not permanently block the daemon.
            query(path, b'\x00\x00', drop, partial=True)
            time.sleep(0.4)
            require(receive_response(path, b'KSIPC/1 STATUS ' + identifier + b'\n', drop) == good,
                    'slow client made daemon permanently unavailable')
            if drop:
                # Root can traverse DAC restrictions; SO_PEERCRED must reject
                # root despite connecting to a service owned by nobody.
                with socket.socket(socket.AF_UNIX) as intruder:
                    intruder.settimeout(2)
                    intruder.connect(str(path))
                    intruder.sendall(frame(b'KSIPC/1 STATUS ' + identifier + b'\n'))
                    try:
                        denied = intruder.recv(512)
                    except ConnectionResetError:
                        denied = b''
                    require(denied == b'', 'different-UID local peer obtained a response')
            else:
                print('M2.3 cross-UID live test: NOT_APPLICABLE (no privilege to switch user)')
            proc.send_signal(signal.SIGTERM)
            _, err = proc.communicate(timeout=5)
            diagnostics += err
            require(proc.returncode == 0, 'manager shutdown failed')
            events = [json.loads(line)['event'] for line in diagnostics.splitlines()]
            require(events == ['manager_starting', 'manager_ready',
                               'manager_stopping', 'manager_stopped'],
                    f'unexpected diagnostic sequence: {events}')
            require(not path.exists() and not path.is_symlink(), 'owned socket not removed')
            require(other.is_symlink(), 'unrelated path was modified')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=4)
    print('M2.3 real IPC: PASS (authorized status, denied operations, bounded wire, cleanup)')


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--binary', required=True, type=Path)
    args = p.parse_args()
    try:
        require(args.binary.resolve().is_file(), 'manager executable missing')
        run(args.binary.resolve())
    except (ValueError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f'M2.3 real IPC: FAIL: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Exercise real manager restart, IPC recovery and audit-session isolation."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import tempfile

from check_m23_ipc_runtime import frame, require, unprivileged
from check_m25_audit_runtime import DROP, UID, GID, private, ready, start, records, command

IDENTIFIER = b'0123456789abcdef'
STATUS = b'KSIPC/1 STATUS ' + IDENTIFIER + b'\n'
HEALTH = b'KSIPC/1 HEALTH ' + IDENTIFIER + b'\n'
STATUS_REPLY = frame(b'KSIPC/1 OK ' + IDENTIFIER + b' LIFECYCLE_ONLY\n')
START = ['manager_starting', 'configuration_default', 'ipc_ready', 'manager_ready']
STOP = ['manager_stopping', 'manager_stopped']
# The child must connect successfully before denial is counted. Only an EOF or
# reset after connect qualifies; a timeout or connection refusal fails the test.
CLIENT = '''import socket, sys, time
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.settimeout(3)
    s.connect(sys.argv[1])
    packet = bytes.fromhex(sys.argv[2])
    mode = sys.argv[3]
    reply = bytearray()
    try:
        if mode == 'fragment':
            for part in (packet[:2], packet[2:8], packet[8:]):
                s.sendall(part)
                time.sleep(0.015)
        else:
            s.sendall(packet)
        if mode == 'half':
            s.shutdown(socket.SHUT_WR)
        # In stall mode the write side stays open: the server must time out.
        while True:
            part = s.recv(257)
            if not part:
                break
            reply.extend(part)
            if len(reply) > 260:
                raise RuntimeError('response exceeded bounds')
    except (ConnectionResetError, BrokenPipeError):
        pass
    print(bytes(reply).hex())
'''


def exchange(path: Path, packet: bytes, mode: str = 'normal',
             identity: str = 'authorized') -> bytes:
    def wrong_gid() -> None:
        os.setgroups([])
        os.setgid(65533)
        os.setuid(UID)

    setup = None
    if identity == 'wrong-gid':
        require(DROP, 'wrong-GID test requires root harness')
        setup = wrong_gid
    elif identity == 'authorized' and DROP:
        setup = unprivileged
    result = subprocess.run([sys.executable, '-I', '-c', CLIENT, str(path), packet.hex(), mode],
                            capture_output=True, text=True, timeout=5, preexec_fn=setup)
    require(result.returncode == 0, 'client exchange failed: ' + mode + '/' + identity)
    return bytes.fromhex(result.stdout.strip())


def health(path: Path) -> tuple[int, int, int, int]:
    reply = exchange(path, frame(HEALTH))
    require(4 < len(reply) <= 260 and struct.unpack('!I', reply[:4])[0] == len(reply) - 4,
            'invalid health frame')
    fields = reply[4:].split()
    require(len(fields) == 14 and fields[:5] == [b'KSIPC/1', b'OK', IDENTIFIER, b'HEALTH', b'RUNNING']
            and fields[8:11] == [b'CONFIG_DEFAULT', b'IPC_READY', b'MONITORING_UNAVAILABLE'],
            'invalid health state')
    require(fields[6].isdigit() and fields[7].isdigit() and int(fields[7]) > 0,
            'resource measurement unavailable')
    return tuple(int(fields[i]) for i in (5, 11, 12, 13))


def probe_state(probe: Path, ipc: Path, expected: str) -> None:
    result = subprocess.run([str(probe), str(ipc)], capture_output=True, text=True,
                            timeout=5, preexec_fn=unprivileged if DROP else None)
    require(result.returncode == 0 and (result.stdout.strip() == expected or
            (expected == 'available' and result.stdout.startswith('available '))),
            'native client availability mismatch: ' + expected)


@contextmanager
def manager(binary: Path, ipc: Path, audit: Path):
    proc = start(binary, ['--ipc-dir', str(ipc), '--audit-dir', str(audit)])
    try:
        diagnostics = ready(proc)
        yield proc, diagnostics
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=4)


def stop(proc: subprocess.Popen, diagnostics: bytes, path: Path, sig: int) -> None:
    proc.send_signal(sig)
    _, err = proc.communicate(timeout=5)
    require(proc.returncode == 0 and not os.path.lexists(path), 'graceful stop or socket cleanup failed')
    require([json.loads(line)['event'] for line in (diagnostics + err).splitlines()] ==
            ['manager_starting', 'manager_ready', 'manager_stopping', 'manager_stopped'],
            'unexpected lifecycle diagnostics')


def audit_events(audit: Path, expected: list[str]) -> list[dict]:
    data = records(audit / 'service-audit.jsonl')
    require([r['event'] for r in data] == expected, 'audit event sequence mismatch')
    return data


def refused(binary: Path, ipc: Path, audit: Path, path: Path) -> None:
    before = path.lstat()
    result = command(binary, '--ipc-dir', str(ipc), '--audit-dir', str(audit))
    require(result.returncode == 5 and b'manager_ready' not in result.stderr,
            'duplicate or stale socket startup did not fail closed')
    after = path.lstat()
    require(stat.S_ISSOCK(after.st_mode) and (before.st_dev, before.st_ino) ==
            (after.st_dev, after.st_ino), 'existing socket was replaced')
    audit_events(audit, ['manager_starting', 'configuration_default', 'ipc_startup_rejected', 'manager_failed'])


def exercise(binary: Path, probe: Path, root: Path) -> None:
    ipc = private(root / 'ipc')
    path = ipc / 'manager.sock'
    first = private(root / 'first')
    probe_state(probe, ipc, 'unavailable')
    with manager(binary, ipc, first) as (proc, diagnostics):
        require(path.is_socket() and stat.S_IMODE(path.stat().st_mode) == 0o600, 'socket metadata')
        require(health(path)[1:] == (0, 0, 0), 'fresh session counters not zero')
        refused(binary, ipc, private(root / 'duplicate'), path)
        require(exchange(path, frame(STATUS), 'fragment') == STATUS_REPLY, 'fragmented request failed')
        # A zero length, boundary+1, and maximum unsigned length must be rejected
        # without allocating or waiting for an advertised body.
        malformed = [struct.pack('!I', n) for n in (0, 65, 0xffffffff)]
        malformed += [frame(STATUS.replace(b'KSIPC/1', b'KSIPC/2')),
                      frame(STATUS.replace(b'abcdef', b'abcdeG')),
                      frame(STATUS.replace(b'\n', b'\x00')), frame(b'SECRET_MARKER'),
                      frame(b'X' * 64)]
        for packet in malformed:
            require(exchange(path, packet) == b'', 'malformed frame disclosed data')
        require(exchange(path, frame(STATUS.replace(b'STATUS', b'ADMIN'))) == b'', 'ADMIN authorized')
        for packet, mode in ((b'\x00\x00', 'half'), (frame(STATUS)[:-1], 'half'),
                             (b'\x00\x00', 'stall'), (frame(STATUS)[:-1], 'stall')):
            require(exchange(path, packet, mode) == b'', 'interrupted frame disclosed data')
            require(exchange(path, frame(STATUS)) == STATUS_REPLY, 'service did not recover after interruption')
        if DROP:
            for identity in ('wrong-uid', 'wrong-gid'):
                require(exchange(path, frame(HEALTH), identity=identity) == b'', 'unauthorized peer obtained health')
            print('M2.8 live wrong-UID and same-UID/wrong-GID denial: PASS')
        else:
            print('M2.8 live distinct peer identities: NOT_APPLICABLE (unprivileged harness)')
        require(health(path)[1:] == (len(malformed) + 1 + 2 * int(DROP), 4, 0),
                'rejection or transport counters inconsistent')
        stop(proc, diagnostics, path, signal.SIGINT)
    expected = START + ['health_authorized', 'status_authorized']
    expected += ['request_rejected'] * len(malformed) + ['administrative_denied']
    expected += ['transport_failed', 'status_authorized'] * 4
    expected += ['authentication_failed'] * (2 * int(DROP)) + ['health_authorized'] + STOP
    data = audit_events(first, expected)
    outcomes = {'manager_starting': 'started', 'manager_stopping': 'started',
                'configuration_default': 'success', 'ipc_ready': 'success',
                'manager_ready': 'success', 'manager_stopped': 'success',
                'health_authorized': 'authorized', 'status_authorized': 'authorized',
                'request_rejected': 'denied', 'administrative_denied': 'denied',
                'authentication_failed': 'denied', 'transport_failed': 'failure'}
    for record in data:
        event, peer = record['event'], record['peer']
        require(record['outcome'] == outcomes[event], 'audit outcome mismatch')
        if event in START + STOP:
            require(peer is None, 'invented lifecycle actor')
        elif event != 'authentication_failed':
            require(peer is not None and (peer['uid'], peer['gid']) == (UID, GID),
                    'authorized identity attribution mismatch')
    if DROP:
        require(data[-5]['peer']['uid'] == 0 and data[-4]['peer']['uid'] == UID and
                data[-4]['peer']['gid'] == 65533, 'cross-identity audit attribution mismatch')
    original = (first / 'service-audit.jsonl').read_bytes()
    probe_state(probe, ipc, 'unavailable')
    print('M2.8 malformed frames, interrupted/stalled clients, counters and graceful stop: PASS')

    second = private(root / 'second')
    with manager(binary, ipc, second) as (proc, _):
        require(health(path)[1:] == (0, 0, 0), 'restart retained old counters')
        probe_state(probe, ipc, 'available')
        proc.kill()
        proc.communicate(timeout=5)
        require(proc.returncode == -signal.SIGKILL and path.is_socket(), 'crash fixture did not leave stale socket')
    crashed = audit_events(second, START + ['health_authorized', 'health_authorized'])
    crashed_bytes = (second / 'service-audit.jsonl').read_bytes()
    probe_state(probe, ipc, 'unavailable')
    refused(binary, ipc, private(root / 'stale'), path)
    # Explicit operator recovery is emulated ONLY inside our private fixture,
    # after the process is reaped and failed restart preserved the inode.
    path.unlink()
    third = private(root / 'third')
    with manager(binary, ipc, third) as (proc, diagnostics):
        require(health(path)[1:] == (0, 0, 0), 'recovered manager counters not fresh')
        stop(proc, diagnostics, path, signal.SIGTERM)
    recovered = audit_events(third, START + ['health_authorized'] + STOP)
    require(len({data[0]['session'], crashed[0]['session'], recovered[0]['session']}) == 3,
            'audit session identity reused')
    require((first / 'service-audit.jsonl').read_bytes() == original and
            (second / 'service-audit.jsonl').read_bytes() == crashed_bytes,
            'earlier audit evidence changed')
    probe_state(probe, ipc, 'unavailable')
    print('M2.8 duplicate startup, restart, crash/stale socket refusal and explicit recovery: PASS')
    print('M2.8 session isolation and preserved prior fixture evidence: PASS')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manager', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix='ks28-', dir='/tmp') as name:
            root = Path(name)
            if DROP:
                os.chown(root, UID, GID)
            exercise(args.manager.resolve(), args.probe.resolve(), root)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('M2.8 lifecycle IPC: FAIL: ' + str(exc), file=sys.stderr)
        return 1
    print('M2.8 lifecycle IPC integration: PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

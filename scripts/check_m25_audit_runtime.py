#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Exercise real audit files, IPC, path safety and fail-closed writes."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

from check_m23_ipc_runtime import frame, query, require, unprivileged
from check_m22_config_runtime import VALID

DROP = os.geteuid() == 0
UID = 65534 if DROP else os.geteuid()
GID = 65534 if DROP else os.getegid()
SECRET = b'0123456789abcdef'
KEYS = {'schema', 'session', 'sequence', 'time_unix_ms', 'service_pid',
        'service_uid', 'service_gid', 'event', 'outcome', 'peer'}


def private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    if DROP:
        os.chown(path, UID, GID)
    return path


def owner_file(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o600)
    if DROP:
        os.chown(path, UID, GID)


def command(binary: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(binary), *args], capture_output=True, timeout=8,
                          preexec_fn=unprivileged if DROP else None)


def start(binary: Path, args: list[str], limit: int | None = None) -> subprocess.Popen:
    def setup() -> None:
        if limit is not None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        if DROP:
            unprivileged()
    return subprocess.Popen([str(binary), *args], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            preexec_fn=setup if DROP or limit is not None else None)


def ready(proc: subprocess.Popen) -> bytes:
    data = b''
    deadline = time.monotonic() + 8
    while b'"event":"manager_ready"' not in data:
        require(time.monotonic() < deadline, 'readiness timeout')
        assert proc.stderr is not None
        if select.select([proc.stderr], [], [], 0.25)[0]:
            part = os.read(proc.stderr.fileno(), 1024)
            require(bool(part), 'daemon exited before readiness')
            data += part
            require(len(data) <= 8192, 'diagnostic bound exceeded')
    return data


def records(path: Path) -> list[dict]:
    raw = path.read_bytes()
    info = path.stat()
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == UID and
            info.st_nlink == 1, 'audit file permissions/identity')
    require(raw.endswith(b'\n') and len(raw) <= 1024 * 1024, 'audit file bounds')
    require(SECRET not in raw and b'SECRET_MARKER' not in raw and
            str(path.parent).encode() not in raw, 'sensitive data leaked')
    lines = raw.splitlines()
    require(all(0 < len(line) < 512 for line in lines), 'record bounds')
    result = [json.loads(line) for line in lines]
    for number, record in enumerate(result, 1):
        require(set(record) == KEYS and record['schema'] == 1 and
                record['sequence'] == number and isinstance(record['time_unix_ms'], int),
                'invalid schema or sequence')
        require(re.fullmatch('[0-9a-f]{32}', record['session']) is not None and
                record['session'] == result[0]['session'] and
                record['service_pid'] == result[0]['service_pid'] and
                record['service_uid'] == UID and record['service_gid'] == GID,
                'incorrect service attribution')
        if record['peer'] is not None:
            require(set(record['peer']) == {'pid', 'uid', 'gid'} and
                    record['peer']['pid'] > 0, 'invalid peer attribution')
    return result


def exercise(binary: Path, root: Path) -> None:
    audit = private(root / 'audit')
    ipc = private(root / 'ipc')
    config = root / 'config'
    owner_file(config, VALID)
    log = audit / 'service-audit.jsonl'
    args = ['--audit-dir', str(audit), '--ipc-dir', str(ipc), '--config', str(config)]
    proc = start(binary, args)
    try:
        ready(proc)
        path = ipc / 'manager.sock'
        require(query(path, frame(b'KSIPC/1 STATUS ' + SECRET + b'\n'), DROP) ==
                frame(b'KSIPC/1 OK ' + SECRET + b' LIFECYCLE_ONLY\n'), 'STATUS regression')
        require(b' HEALTH RUNNING ' in query(path, frame(b'KSIPC/1 HEALTH ' + SECRET + b'\n'), DROP),
                'HEALTH regression')
        require(query(path, frame(b'KSIPC/1 ADMIN ' + SECRET + b'\n'), DROP) == b'', 'ADMIN accepted')
        require(query(path, frame(b'SECRET_MARKER\n{"event":"fake"}'), DROP) == b'', 'bad request accepted')
        require(query(path, b'\x00\x00', DROP) == b'', 'partial frame accepted')
        if DROP:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2)
                client.connect(str(path))
                try:
                    client.sendall(frame(b'KSIPC/1 HEALTH ' + SECRET + b'\n'))
                    denied = client.recv(512)
                except (ConnectionResetError, BrokenPipeError):
                    denied = b''
                require(denied == b'', 'cross-UID access')
        proc.send_signal(signal.SIGTERM)
        _, err = proc.communicate(timeout=6)
        require(proc.returncode == 0 and not path.exists(), 'shutdown regression')
        require(SECRET not in err and b'SECRET_MARKER' not in err, 'diagnostic leak')
        data = records(log)
        expected = ['manager_starting', 'configuration_validated', 'ipc_ready', 'manager_ready',
                    'status_authorized', 'health_authorized', 'administrative_denied',
                    'request_rejected', 'transport_failed']
        if DROP:
            expected.append('authentication_failed')
        expected += ['manager_stopping', 'manager_stopped']
        require([r['event'] for r in data] == expected, 'incorrect audit ordering')
        require([r['outcome'] for r in data[:9]] == ['started', 'success', 'success', 'success',
                'authorized', 'authorized', 'denied', 'denied', 'failure'], 'incorrect outcomes')
        require(all(r['peer']['uid'] == UID and r['peer']['gid'] == GID for r in data[4:9]),
                'kernel peer identity mismatch')
        require(all(r['peer'] is None for r in data[:4] + data[-2:]), 'invented peer identity')
        if DROP:
            require(data[-3]['peer']['uid'] == 0 and data[-3]['outcome'] == 'denied',
                    'cross-UID denial missing attribution')
        old = log.read_bytes()
        repeated = command(binary, *args)
        require(repeated.returncode == 6 and log.read_bytes() == old, 'existing log overwritten')
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=4)

    bad_config = private(root / 'bad-config-audit')
    owner_file(config, 'SECRET_MARKER = invalid\n')
    failed = command(binary, '--audit-dir', str(bad_config), '--config', str(config))
    require(failed.returncode == 4 and b'manager_ready' not in failed.stderr, 'invalid config accepted')
    data = records(bad_config / 'service-audit.jsonl')
    require([r['event'] for r in data] == ['manager_starting', 'configuration_rejected',
                                          'manager_failed'], 'rejected config not audited')
    require(data[0]['session'] != records(log)[0]['session'], 'session reused')

    bad_ipc = private(root / 'bad-ipc-audit')
    failed = command(binary, '--audit-dir', str(bad_ipc), '--ipc-dir', str(root / 'missing'))
    require(failed.returncode == 5, 'invalid IPC accepted')
    require([r['event'] for r in records(bad_ipc / 'service-audit.jsonl')] ==
            ['manager_starting', 'configuration_default', 'ipc_startup_rejected', 'manager_failed'],
            'IPC startup failure not audited')

    # File-size limit produces a real short write/EFBIG after readiness.
    limited = private(root / 'limited')
    proc = start(binary, ['--audit-dir', str(limited), '--ipc-dir', str(ipc)], 2048)
    try:
        ready(proc)
        for _ in range(20):
            response = query(ipc / 'manager.sock', frame(b'KSIPC/1 STATUS ' + SECRET + b'\n'), DROP)
            if not response:
                break
        else:
            raise ValueError('audit failure never denied response')
        _, err = proc.communicate(timeout=6)
        require(proc.returncode == 6 and b'audit unavailable or incomplete' in err and
                not (ipc / 'manager.sock').exists(), 'audit write failure did not stop service')
        require((limited / 'service-audit.jsonl').stat().st_size <= 2048, 'file limit exceeded')
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=4)


def paths(binary: Path, root: Path) -> None:
    public = private(root / 'public')
    public.chmod(0o755)
    target = private(root / 'target')
    alias = root / 'alias'
    alias.symlink_to(target, target_is_directory=True)
    inner = private(target / 'inner')
    victim = root / 'victim'
    owner_file(victim, 'untouched')
    for entry in ('symlink', 'hardlink', 'fifo', 'regular'):
        directory = private(root / entry)
        log = directory / 'service-audit.jsonl'
        if entry == 'symlink':
            log.symlink_to(victim)
        elif entry == 'hardlink':
            os.link(victim, log)
        elif entry == 'fifo':
            os.mkfifo(log, 0o600)
        else:
            owner_file(log, 'untouched')
        require(command(binary, '--audit-dir', str(directory)).returncode == 6,
                'unsafe existing sink accepted')
    for path in (public, alias, alias / inner.name, root / 'missing'):
        result = command(binary, '--audit-dir', str(path))
        require(result.returncode == 6 and b'manager_ready' not in result.stderr,
                'unsafe directory accepted')
    require(victim.read_text() == 'untouched' and not (target / 'service-audit.jsonl').exists(),
            'existing target modified')
    require(command(binary, '--audit-dir', str(target), '--audit-dir', str(target)).returncode == 2,
            'duplicate audit option accepted')
    require(command(binary, '--audit-dir', '').returncode == 2, 'empty option accepted')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix='ks-m25-') as name:
            root = Path(name)
            if DROP:
                os.chown(root, UID, GID)
            exercise(args.binary.resolve(), root)
            paths(args.binary.resolve(), root)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'M2.5 audit runtime: FAIL: {exc}', file=sys.stderr)
        return 1
    print('M2.5 cross-UID audit: ' + ('PASS' if DROP else 'NOT_APPLICABLE (unprivileged harness)'))
    print('M2.5 live audit: PASS (attribution, redaction, paths, ordering, fail-closed writes)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

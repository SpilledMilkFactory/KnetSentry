#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""M2.2 real daemon configuration test; no network or privileged operations."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

VALID = ("schema_version = 1\nmode = lifecycle_only\nmonitoring_enabled = false\n"
         "network_listeners_enabled = false\npacket_capture_enabled = false\n"
         "public_intelligence_enabled = false\nprivileged_actions_enabled = false\n")


def require(ok: bool, why: str) -> None:
    if not ok:
        raise ValueError(why)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--binary', type=Path, required=True)
    args = p.parse_args()
    binary = args.binary.resolve()
    require(binary.is_file(), 'compiled daemon missing')
    drop = os.geteuid() == 0

    def unprivileged() -> None:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)

    def command(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(binary), *arguments], capture_output=True, text=True,
                              timeout=8, check=False,
                              preexec_fn=unprivileged if drop else None)

    try:
        with tempfile.TemporaryDirectory(prefix='knetsentry-m22-') as dirname:
            directory = Path(dirname)
            if drop:
                os.chown(directory, 65534, 65534)
            fixture = directory / 'manager.conf'

            def write(data: str, mode: int = 0o600) -> None:
                fixture.unlink(missing_ok=True)
                fixture.write_bytes(data.encode('utf-8'))
                os.chmod(fixture, mode)
                if drop:
                    os.chown(fixture, 65534, 65534)

            write(VALID)
            ready = command('--check-config', str(fixture))
            require(ready.returncode == 0 and 'schema v1: valid' in ready.stdout,
                    'valid file rejected')
            require(str(fixture) not in ready.stdout + ready.stderr,
                    'path leaked from validator')
            invalid_cases = [
                ('future schema', VALID.replace('schema_version = 1', 'schema_version = 99')),
                ('unknown field', VALID + 'unexpected = true\n'),
                ('duplicate field', VALID + 'mode = lifecycle_only\n'),
                ('monitoring', VALID.replace('monitoring_enabled = false', 'monitoring_enabled = true')),
                ('packet capture', VALID.replace('packet_capture_enabled = false', 'packet_capture_enabled = true')),
                ('listener', VALID.replace('network_listeners_enabled = false', 'network_listeners_enabled = true')),
                ('public egress', VALID.replace('public_intelligence_enabled = false', 'public_intelligence_enabled = true')),
                ('privileged actions', VALID.replace('privileged_actions_enabled = false', 'privileged_actions_enabled = true')),
                ('missing key', VALID.replace('mode = lifecycle_only\n', '')),
            ]
            for label, data in invalid_cases:
                write(data)
                result = command('--check-config', str(fixture))
                require(result.returncode == 4 and result.stdout == '',
                        f'{label}: invalid file accepted')
                require(str(fixture) not in result.stderr,
                        f'{label}: path leaked')
            write(VALID, 0o644)
            require(command('--check-config', str(fixture)).returncode == 4,
                    'world-readable config accepted')
            write(VALID, 0o660)
            require(command('--check-config', str(fixture)).returncode == 4,
                    'group-writable config accepted')
            write(VALID, 0o600)
            link = directory / 'alias.conf'
            link.symlink_to(fixture)
            require(command('--check-config', str(link)).returncode == 4,
                    'symlink config accepted')
            require(command('--check-config', str(directory)).returncode == 4,
                    'directory config accepted')
            fifo = directory / 'pipe.conf'
            os.mkfifo(fifo, 0o600)
            if drop:
                os.chown(fifo, 65534, 65534)
            require(command('--check-config', str(fifo)).returncode == 4,
                    'FIFO config accepted or blocked')
            require(command('--check-config', 'relative.conf').returncode == 4,
                    'relative path accepted')
            require(command('--check-config', str(directory / 'missing.conf')).returncode == 4,
                    'missing config accepted')
            require(command('--check-config', str(directory / '..' / 'manager.conf')).returncode == 4,
                    'dot-dot path accepted')
            write(VALID + 'a' * 4096)
            require(command('--check-config', str(fixture)).returncode == 4,
                    'oversized config accepted')
            write(VALID)
            proc = subprocess.Popen([str(binary), '--config', str(fixture)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, preexec_fn=unprivileged if drop else None)
            try:
                import select
                import time
                start = time.monotonic()
                collected = ''
                while '"event":"manager_ready"' not in collected:
                    require(time.monotonic() - start < 10, 'daemon did not reach ready')
                    assert proc.stderr is not None
                    readable, _, _ = select.select([proc.stderr], [], [], 1)
                    if readable:
                        chunk = os.read(proc.stderr.fileno(), 1024)
                        require(bool(chunk), 'daemon exited before ready')
                        collected += chunk.decode('utf-8')
                proc.send_signal(signal.SIGTERM)
                out, err = proc.communicate(timeout=10)
                collected += err
                require(proc.returncode == 0 and out == '', 'valid daemon shutdown failed')
                records = [json.loads(line) for line in collected.splitlines()]
                require([r['event'] for r in records] == [
                    'manager_starting', 'manager_ready', 'manager_stopping', 'manager_stopped'
                ], 'configured lifecycle diagnostics incorrect')
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)
            # Malformed explicit configuration MUST fail before "ready".
            write(VALID.replace('packet_capture_enabled = false', 'packet_capture_enabled = true'))
            denied = command('--config', str(fixture))
            require(denied.returncode == 4 and 'manager_ready' not in denied.stderr,
                    'invalid daemon configuration fell back to defaults')
            require('manager_failed' in denied.stderr and str(fixture) not in denied.stderr,
                    'missing fixed diagnostic or config path leaked')
            print('M2.2 configured daemon runtime: PASS (valid, fail-closed and hostile files)')
    except (ValueError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f'M2.2 configured daemon runtime: FAIL: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

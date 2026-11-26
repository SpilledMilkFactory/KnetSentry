#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Actual agent reports through an explicitly inherited pipe, synthetic FIM only."""
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def report(proc):
    deadline = time.monotonic() + 7
    raw = bytearray()
    while time.monotonic() < deadline and len(raw) < 160:
        if not select.select([proc.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
            break
        byte = os.read(proc.stdout.fileno(), 1)
        if byte == b'\n':
            fields = raw.decode('ascii').split('\t')
            require(len(fields) == 7 and fields[0] == 'KSSTAT1', 'invalid aggregate report')
            return fields[1:]
        if not byte:
            break
        raw += byte
    raise RuntimeError('bounded aggregate report missing')


def launch(binary, *args):
    # Shell only performs fixed descriptor routing; user-controlled arguments
    # are passed separately and never interpolated into shell code.
    return subprocess.Popen(['bash', '-c', 'exec "$@" 3>&1 1>/dev/null', 'status-fixture', binary,
                             '--status-stream', '--run', '--schema-version', '1', '--collectors', *args],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)


def stop(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        raise
    finally:
        proc.stdout.close()
        proc.stderr.close()


def main():
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    require(os.geteuid() != 0, 'run as ordinary user')
    with tempfile.TemporaryDirectory(prefix='ks59-') as directory:
        path = Path(directory) / 'approved'
        path.write_text('synthetic\n')
        policy = f'v1;collector=fim;allow-path={path};redact=fim-content;redact=fim-slot'
        proc = launch(binary, 'fim', '--path', str(path), '--privacy-policy', policy)
        try:
            first = report(proc)
            require(first[:2] == ['fim-metadata', 'active'] and first[3:] == ['0', '0', '-'], 'initial rate must be unknown')
            path.chmod(0o400)
            deadline = time.monotonic() + 8
            observed = False
            while time.monotonic() < deadline:
                row = report(proc)
                require(row[:2] == ['fim-metadata', 'active'] and row[-1] == '-' and int(row[4]) > 0,
                        'invalid FIM aggregate')
                if row[3] == '1':
                    observed = True
                    break
                require(row[3] == '0', 'unexpected observation count')
            require(observed, 'metadata change was not reported')
            replacement = Path(directory) / 'replacement'
            replacement.symlink_to(Path(directory) / 'unapproved')
            replacement.replace(path)
            row = report(proc)
            require(row[:2] == ['fim-metadata', 'failed'] and row[3:] == ['0', '0', '-'], 'unsafe observation not reported')
            require(proc.wait(timeout=5) == 1, 'unsafe observation must terminate')
        finally:
            stop(proc)
        proc = launch(binary, 'none')
        try:
            require(report(proc)[:2] == ['none', 'idle'], 'lifecycle-only mode not distinguished')
            proc.stdout.close()
            # EPIPE must not terminate the collecting process.
            time.sleep(1.5)
            require(proc.poll() is None, 'observer disconnect stopped agent')
        finally:
            stop(proc)
        require(proc.returncode == 0, 'agent shutdown after observer disconnect')
        target = Path(directory) / 'not-a-pipe'
        target.write_bytes(b'synthetic')
        result = subprocess.run(['bash', '-c', 'exec "$@" 3>>"$STATUS_TEST_FILE"', 'status-fixture', binary,
                                 '--status-stream', '--run', '--schema-version', '1', '--collectors', 'none'],
                                env={**os.environ, 'STATUS_TEST_FILE': str(target)}, capture_output=True, timeout=5)
        require(result.returncode == 2 and target.read_bytes() == b'synthetic', 'non-pipe descriptor accepted or mutated')
    print('M5.9 actual agent aggregate reports, local observation rate, unsafe-source failure and observer disconnect: PASS')


if __name__ == '__main__':
    main()

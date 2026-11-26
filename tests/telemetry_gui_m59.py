#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Actual QML cards with a synthetic single-writer status pipe; no host collection."""
import os
import select
import subprocess
import sys
import time


def expect(proc, expected):
    deadline = time.monotonic() + 10
    received = bytearray()
    while time.monotonic() < deadline and len(received) < len(expected):
        if not select.select([proc.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
            break
        part = os.read(proc.stdout.fileno(), len(expected) - len(received))
        if not part:
            break
        received.extend(part)
    if received != expected:
        raise RuntimeError('rendered status check missing or invalid')


def main():
    with subprocess.Popen([sys.argv[1], '--agent-status-stdin', '--self-test-telemetry'],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          bufsize=0) as proc:
        try:
            # Send recent reports until the actual application has completed
            # QML startup; a single pre-start sample could expire on a busy CI host.
            deadline = time.monotonic() + 9
            while time.monotonic() < deadline:
                frame = f'KSSTAT1\tjournal\tactive\t{time.monotonic_ns() // 1000000}\t2\t1000\t12\n'
                data = frame.encode('ascii')
                if proc.stdin.write(data) != len(data):
                    raise RuntimeError('short fixture report write')
                if select.select([proc.stdout], [], [], 0.25)[0]:
                    break
            expect(proc, b'M5.9 rendered current aggregate: PASS\n')
            proc.stdin.close()
            expect(proc, b'M5.9 rendered disconnect clears measurements: PASS\n')
            if proc.wait(timeout=5) != 0:
                raise RuntimeError('desktop status test failed')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    print('M5.9 actual Dashboard/Assets bindings and disconnected-state clearing: PASS')


if __name__ == '__main__':
    main()

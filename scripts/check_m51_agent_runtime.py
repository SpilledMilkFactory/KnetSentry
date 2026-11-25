#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Actual independent agent process, strict startup, privileges and signal shutdown."""
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def main():
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    args = ['--run', '--schema-version', '1', '--collectors', 'none']
    for invalid in ([], args[:-1], args + ['--extra'],
                    ['--run', '--schema-version', '2', '--collectors', 'none'],
                    ['--run', '--schema-version', '1', '--collectors', 'private-canary']):
        result = subprocess.run([binary, *invalid], capture_output=True, timeout=5)
        require(result.returncode == 2 and not result.stdout and
                result.stderr == b'knetsentry-agent: configuration rejected\n',
                'unsafe configuration accepted or reflected')
    require(os.getuid() != 0 and os.getgid() != 0, 'positive qualification requires ordinary user')
    with tempfile.TemporaryDirectory(prefix='ks-agent-') as directory:
        for sig in (signal.SIGTERM, signal.SIGINT):
            with subprocess.Popen([binary, *args], cwd=directory, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
                try:
                    require(select.select([proc.stdout], [], [], 5)[0], 'readiness timeout')
                    require(proc.stdout.readline() == b'knetsentry-agent: ready; collectors=0; monitoring=unavailable; network=disabled\n',
                            'unexpected readiness')
                    status = dict(line.split(':', 1) for line in Path(f'/proc/{proc.pid}/status').read_text().splitlines() if ':' in line)
                    for field, expected in (('Uid', os.getuid()), ('Gid', os.getgid())):
                        require([int(x) for x in status[field].split()] == [expected] * 4, 'identity mismatch')
                    for field in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb'):
                        require(int(status[field], 16) == 0, 'capability authority present')
                    require(status['NoNewPrivs'].strip() == '1' and status['Umask'].strip() == '0077',
                            'runtime privilege/umask mismatch')
                    fds = Path(f'/proc/{proc.pid}/fd')
                    require(set(p.name for p in fds.iterdir()) == {'0', '1', '2'}, 'unexpected agent descriptors')
                    require(proc.poll() is None, 'agent not independently running')
                    proc.send_signal(sig)
                    out, err = proc.communicate(timeout=5)
                    require(proc.returncode == 0 and out == b'knetsentry-agent: stopped\n' and not err, 'unclean shutdown')
                    require(not list(Path(directory).iterdir()), 'unexpected filesystem writes')
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
    print('M5.1 strict configuration, independent process, identity, empty capabilities, no-new-privileges, descriptors and SIGTERM/SIGINT: PASS')


if __name__ == '__main__':
    main()

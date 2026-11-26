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
import time


READY = b'knetsentry-agent: ready; collectors=0; monitoring=unavailable; network=disabled\n'
STARTUP_ERRORS = {
    b'knetsentry-agent: privilege policy rejected\n',
    b'knetsentry-agent: signal setup failed\n',
    *(b'knetsentry-agent: privilege policy rejected: ' + reason + b'\n' for reason in (
        b'identity query failed', b'zero or mismatched identity', b'capability query failed',
        b'active capability authority', b'no-new-privileges setup failed',
        b'inheritable capability removal failed', b'capability readback failed',
        b'nonempty capability readback')),
}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def process_status(pid):
    return dict(line.split(':', 1) for line in
                Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)


def expect_ready(proc):
    # A readable pipe can indicate EOF or only a partial line. Use bounded
    # unbuffered reads so the timeout covers the whole readiness message.
    deadline = time.monotonic() + 5
    received = bytearray()
    while len(received) < len(READY):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([proc.stdout], [], [], remaining)[0]:
            raise RuntimeError(f'readiness timeout ({len(received)} bytes)')
        chunk = os.read(proc.stdout.fileno(), len(READY) - len(received))
        if not chunk:
            # EOF without readiness: capture the exit code and known fixed
            # startup diagnostics, never reflect arbitrary child output.
            _, err = proc.communicate(timeout=5)
            diagnostic = err.decode('ascii').strip() if err in STARTUP_ERRORS else f'unrecognized stderr ({len(err)} bytes)'
            raise RuntimeError(f'agent exited before readiness: exit={proc.returncode}; '
                               f'stdout={len(received)} bytes; {diagnostic}')
        received.extend(chunk)
        require(READY.startswith(received), 'unexpected readiness bytes')
    require(received == READY, 'unexpected readiness')


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
    for invalid in (['--run', '--schema-version', '1', '--collectors', 'audit'],
                    ['--run', '--schema-version', '1', '--collectors', 'audit', '--state-dir', '/tmp/private', '--buffer-for', 'private-canary'],
                    ['--run', '--schema-version', '1', '--collectors', 'audit', '--state-dir', '/tmp/private', '--buffer-for', '0' * 96],
                    ['--run', '--schema-version', '1', '--collectors', 'audit', '--unit', 'audit.service', '--state-dir', '/tmp/private'],
                    ['--run', '--schema-version', '1', '--collectors', 'authentication'],
                    ['--run', '--schema-version', '1', '--collectors', 'authentication', '--unit', 'other.service', '--state-dir', '/tmp/private'],
                    ['--run', '--schema-version', '1', '--collectors', 'authentication', '--unit', 'ssh@*.service', '--state-dir', '/tmp/private'],
                    ['--run', '--schema-version', '1', '--collectors', 'journal'],
                    ['--run', '--schema-version', '1', '--collectors', 'journal', '--unit', '*.service', '--state-dir', '/tmp/private'],
                    ['--run', '--schema-version', '1', '--collectors', 'journal', '--unit', 'fixture.service', '--state-dir', '/tmp/../private']):
        result = subprocess.run([binary, *invalid], capture_output=True, timeout=5)
        require(result.returncode == 2 and not result.stdout and
                result.stderr == b'knetsentry-agent: configuration rejected\n',
                'unsafe journal configuration accepted or reflected')
    require(os.getuid() != 0 and os.getgid() != 0, 'positive qualification requires ordinary user')
    caller = process_status(os.getpid())
    # Only capability masks are logged, never the host inventory or credentials.
    print('M5.1 caller capability masks: ' + ' '.join(
        f'{field}={int(caller[field], 16):016x}' for field in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')), flush=True)
    with tempfile.TemporaryDirectory(prefix='ks-agent-') as directory:
        # Reject a missing directory before opening any journal.
        result = subprocess.run([binary, '--run', '--schema-version', '1', '--collectors', 'journal',
                                 '--unit', 'fixture.service', '--state-dir', directory + '/missing',
                                 '--privacy-policy', 'v1;collector=journal;allow-unit=fixture.service;permit=journal-identifiers'],
                                capture_output=True, timeout=5)
        require(result.returncode == 1 and not result.stdout and
                result.stderr == b'knetsentry-agent: journal rejected: unsafe or busy state directory\n',
                'journal mode did not fail closed before source access')
        result = subprocess.run([binary, '--run', '--schema-version', '1', '--collectors', 'authentication',
                                 '--unit', 'ssh.service', '--state-dir', directory + '/missing',
                                 '--privacy-policy', 'v1;collector=authentication;allow-unit=ssh.service;permit=journal-identifiers;permit=auth-message'],
                                capture_output=True, timeout=5)
        require(result.returncode == 1 and not result.stdout and
                result.stderr == b'knetsentry-agent: journal rejected: unsafe or busy state directory\n',
                'authentication mode did not fail closed before source access')
        result = subprocess.run([binary, '--run', '--schema-version', '1', '--collectors', 'audit',
                                 '--state-dir', directory + '/missing', '--privacy-policy',
                                 'v1;collector=audit;permit=journal-identifiers;permit=audit-identifiers'], capture_output=True, timeout=5)
        require(result.returncode == 1 and not result.stdout and
                result.stderr == b'knetsentry-agent: journal rejected: unsafe or busy state directory\n',
                'audit mode did not fail closed before source access')
        result = subprocess.run([binary, '--run', '--schema-version', '1', '--collectors', 'journal',
                                 '--unit', 'fixture.service', '--state-dir', directory + '/missing',
                                 '--buffer-for', 'a' * 96, '--privacy-policy',
                                 'v1;collector=journal;allow-unit=fixture.service;permit=journal-identifiers;permit=buffering'], capture_output=True, timeout=5)
        require(result.returncode == 1 and not result.stdout and
                result.stderr == b'knetsentry-agent: journal rejected: unsafe or busy state directory\n',
                'buffer mode did not reject missing private directory')
        for sig in (signal.SIGTERM, signal.SIGINT):
            with subprocess.Popen([binary, *args], cwd=directory, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0) as proc:
                try:
                    expect_ready(proc)
                    status = process_status(proc.pid)
                    for field, expected in (('Uid', os.getuid()), ('Gid', os.getgid())):
                        require([int(x) for x in status[field].split()] == [expected] * 4, 'identity mismatch')
                    for field in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb'):
                        require(int(status[field], 16) == 0, f'capability authority present: {field}')
                    require(status['NoNewPrivs'].strip() == '1' and status['Umask'].strip() == '0077',
                            'runtime privilege/umask mismatch')
                    fds = Path(f'/proc/{proc.pid}/fd')
                    require(set(p.name for p in fds.iterdir()) == {'0', '1', '2'}, 'unexpected agent descriptors')
                    require(proc.poll() is None, 'agent not independently running')
                    proc.send_signal(sig)
                    out, err = proc.communicate(timeout=5)
                    require(proc.returncode == 0 and out == b'knetsentry-agent: stopped\n' and not err,
                            f'unclean shutdown: exit={proc.returncode}; stdout={len(out)} bytes; stderr={len(err)} bytes')
                    require(not list(Path(directory).iterdir()), 'unexpected filesystem writes')
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
    after = process_status(os.getpid())
    fields = ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')
    require(all(int(after[field], 16) == int(caller[field], 16) for field in fields),
            'caller capability masks changed')
    if int(caller['CapInh'], 16) != 0 and all(int(caller[field], 16) == 0 for field in fields[1:]):
        print('M5.1 inherited-only capability removal with unchanged caller: PASS')
    print('M5.1 strict configuration, independent process, identity, empty capabilities, no-new-privileges, descriptors and SIGTERM/SIGINT: PASS')


if __name__ == '__main__':
    main()

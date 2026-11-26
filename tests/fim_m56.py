#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Actual unprivileged agent regression using disposable synthetic files."""
import ctypes
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
from contextlib import contextmanager
import time

READY = b'knetsentry-agent: ready; collectors=1; fim=local; monitoring=unavailable; network=disabled'
START_ERROR = b'knetsentry-agent: fim rejected: unsafe or unavailable baseline\n'
POLL_ERROR = b'knetsentry-agent: fim rejected: unsafe or unstable observation; coverage=unknown\n'
CONFIG_ERROR = b'knetsentry-agent: configuration rejected\n'


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def command(binary, *paths):
    args = [binary, '--run', '--schema-version', '1', '--collectors', 'fim']
    for path in paths:
        args.extend(['--path', str(path)])
    policy = "v1;collector=fim;permit=file-content" + "".join(f";allow-path={path}" for path in paths)
    return args + ["--privacy-policy", policy]


def line(proc, expected, timeout=8):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while time.monotonic() < deadline:
        if not select.select([proc.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
            break
        part = os.read(proc.stdout.fileno(), 1)
        if not part:
            break
        if part == b'\n':
            require(data == expected, 'unexpected FIM diagnostic (private output withheld)')
            return
        data += part
        require(len(data) < 256, 'oversized FIM diagnostic')
    raise RuntimeError(f'FIM diagnostic missing; exit={proc.poll()}')


def rejection(args, code, error):
    result = subprocess.run(args, capture_output=True, timeout=5)
    require(result.returncode == code and not result.stdout and result.stderr == error,
            f'FIM rejection mismatch; exit={result.returncode}')


def event(proc, slot, kind):
    line(proc, f'knetsentry-agent: fim change; slot={slot}; kind={kind}'.encode())


def launch(binary, *paths):
    return subprocess.Popen(command(binary, *paths), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)


def finish(proc, error=None):
    if error is None:
        proc.send_signal(signal.SIGTERM)
    out, err = proc.communicate(timeout=8)
    if error is None:
        require(proc.returncode == 0 and out == b'knetsentry-agent: stopped\n' and not err,
                'FIM shutdown or unexpected event')
    else:
        require(proc.returncode == 1 and not out and err == error, 'FIM unsafe observation not rejected')


def cleanup(proc):
    if proc.poll() is None:
        proc.kill()
        proc.communicate(timeout=5)


@contextmanager
def access_guard(path):
    # Real kernel observation of unexpected content opens/reads on the canary.
    # Confirm the watch is functional with a deliberate test-side read first.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_init1.restype = ctypes.c_int
    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    libc.inotify_add_watch.restype = ctypes.c_int
    fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
    require(fd >= 0, 'cannot establish canary access watch')
    try:
        require(libc.inotify_add_watch(fd, os.fsencode(path), 0x21) >= 0,
                'cannot watch unapproved canary')  # IN_OPEN | IN_ACCESS
        path.read_bytes()
        require(bool(select.select([fd], [], [], 1)[0]), 'canary watch negative control failed')
        os.read(fd, 4096)
        yield fd
        require(not select.select([fd], [], [], 0)[0], 'unapproved canary was opened or read')
    finally:
        os.close(fd)


def main():
    binary = sys.argv[1]
    require(os.getuid() != 0, 'run FIM regression as ordinary user')
    with tempfile.TemporaryDirectory(prefix='ks-fim-m56-', dir='/tmp') as tmp:
        root = Path(tmp)
        approved = root / 'approved'
        approved.mkdir()
        watched = approved / 'watched'
        missing = approved / 'missing'
        unrelated = root / 'unapproved-canary'
        watched.write_bytes(b'AAAA')
        unrelated.write_bytes(b'private synthetic marker')
        sibling = approved / 'unapproved-sibling'
        sibling.write_bytes(b'untouched')
        with access_guard(unrelated):
            for paths in ((), ('relative',), ('/tmp/../etc/passwd',), ('/tmp//bad',), ('/tmp/*',),
                          (watched, watched), tuple(root / str(n) for n in range(9))):
                rejection(command(binary, *paths), 2, CONFIG_ERROR)
            rejection(command(binary, watched) + ['--buffer-for', 'a' * 96], 2, CONFIG_ERROR)
            rejection(command(binary, root / 'missing-parent' / 'file'), 1, START_ERROR)
            rejection(command(binary, approved), 1, START_ERROR)
            link = approved / 'symlink'
            link.symlink_to(unrelated)
            rejection(command(binary, link), 1, START_ERROR)
            link.unlink()
            os.link(unrelated, link)
            rejection(command(binary, link), 1, START_ERROR)
            link.unlink()
            os.mkfifo(link)
            rejection(command(binary, link), 1, START_ERROR)
            link.unlink()
            alias = root / 'alias'
            alias.symlink_to(approved, target_is_directory=True)
            rejection(command(binary, alias / 'watched'), 1, START_ERROR)
            rejection(command(binary, '/proc/self/status'), 1, START_ERROR)
            large = approved / 'large'
            with large.open('wb') as stream:
                stream.truncate(1024 * 1024 + 1)
            rejection(command(binary, large), 1, START_ERROR)
            large.unlink()
            watched.chmod(0)
            rejection(command(binary, watched), 1, START_ERROR)
            watched.chmod(0o600)
            limit = approved / 'limit'
            with limit.open('wb') as stream:
                stream.truncate(1024 * 1024)
            with launch(binary, limit, *(approved / f'absent-{n}' for n in range(7))) as proc:
                try:
                    line(proc, READY)
                    finish(proc)
                finally:
                    cleanup(proc)
            limit.unlink()
            with launch(binary, watched, missing) as proc:
                try:
                    line(proc, READY)
                    status = dict(row.split(':', 1) for row in Path(f'/proc/{proc.pid}/status').read_text().splitlines() if ':' in row)
                    require(all(int(status[key], 16) == 0 for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')),
                            'FIM process retains capabilities')
                    require(status['NoNewPrivs'].strip() == '1', 'FIM process permits new privileges')
                    sibling.write_bytes(b'changed unapproved marker')
                    require(not select.select([proc.stdout], [], [], 1.3)[0], 'unapproved sibling produced an event')
                    old = watched.stat()
                    watched.write_bytes(b'BBBB')
                    os.utime(watched, ns=(old.st_atime_ns, old.st_mtime_ns))
                    event(proc, 1, 'content-changed')
                    watched.chmod(0o400)
                    event(proc, 1, 'metadata-changed')
                    replacement = approved / 'replacement'
                    replacement.write_bytes(b'BBBB')
                    replacement.replace(watched)
                    event(proc, 1, 'replaced')
                    watched.unlink()
                    event(proc, 1, 'deleted')
                    watched.write_bytes(b'CCCC')
                    event(proc, 1, 'created')
                    missing.write_bytes(b'')
                    event(proc, 2, 'created')
                    require(not select.select([proc.stdout], [], [], 1.3)[0], 'unchanged files produced an event')
                    finish(proc)
                finally:
                    cleanup(proc)
            for kind in ('symlink', 'hardlink', 'fifo', 'oversize', 'parent'):
                with launch(binary, watched) as proc:
                    try:
                        line(proc, READY)
                        if kind == 'parent':
                            moved = root / 'moved'
                            approved.rename(moved)
                            approved.mkdir()
                            watched.write_bytes(b'foreign replacement')
                        else:
                            watched.unlink()
                            if kind == 'symlink':
                                watched.symlink_to(unrelated)
                            elif kind == 'hardlink':
                                os.link(unrelated, watched)
                            elif kind == 'fifo':
                                os.mkfifo(watched)
                            else:
                                with watched.open('wb') as stream:
                                    stream.truncate(1024 * 1024 + 1)
                        finish(proc, POLL_ERROR)
                    finally:
                        cleanup(proc)
                watched.unlink()
                if kind == 'parent':
                    approved.rmdir()
                    moved.rename(approved)
                else:
                    watched.write_bytes(b'baseline')
            with launch(binary, watched) as proc:
                try:
                    line(proc, READY)
                    require(not select.select([proc.stdout], [], [], 1.3)[0], 'fresh baseline emitted a change')
                    finish(proc)
                finally:
                    cleanup(proc)
    print('M5.6 explicit paths, content/metadata/replacement/create/delete, scope, unsafe substitutions and shutdown: PASS')


if __name__ == '__main__':
    main()

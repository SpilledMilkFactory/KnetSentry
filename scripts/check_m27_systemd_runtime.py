#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Explicit administrator-only acceptance of the installed development unit.
Never installs, enables, resets a failed unit, or stops a previously active unit.
Run on a disposable systemd-booted Ubuntu 26.04 VM or approved test host.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import time

from verify_m27_systemd import LIVE_UNIT_EXPECTED, UNIT, require, validate_live_unit_state

NAME = 'knetsentry-manager.service'
STATE = Path('/var/lib/knetsentry')
RUNTIME = Path('/run/knetsentry')
SOCKET = RUNTIME / 'manager.sock'
INSTALL = Path('/usr/local/libexec/knetsentry')
QUERY = '''import socket, struct
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.settimeout(3)
    s.connect('/run/knetsentry/manager.sock')
    request = b'KSIPC/1 HEALTH 0123456789abcdef\\n'
    s.sendall(struct.pack('!I', len(request)) + request)
    def read(n):
        out = b''
        while len(out) < n:
            part = s.recv(n - len(out))
            if not part: raise RuntimeError('incomplete response')
            out += part
        return out
    size = struct.unpack('!I', read(4))[0]
    assert 0 < size <= 256
    fields = read(size).split()
    assert len(fields) == 14 and fields[:5] == [b'KSIPC/1', b'OK', b'0123456789abcdef', b'HEALTH', b'RUNNING']
    assert fields[9:11] == [b'IPC_READY', b'MONITORING_UNAVAILABLE']
'''
DENY = '''import socket
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.settimeout(2)
    try: s.connect('/run/knetsentry/manager.sock')
    except PermissionError: pass
    else: raise RuntimeError('unexpected socket access')
'''


def command(*args: str, timeout: int = 25) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    require(result.returncode == 0, f'{args[0]} command failed (exit {result.returncode})')
    return result.stdout.strip()


def prop(key: str) -> str:
    return command('systemctl', 'show', NAME, '--property=' + key, '--value')


def unit_preflight() -> None:
    require(Path('/proc/1/comm').read_text().strip() == 'systemd',
            'live test requires a systemd-booted host')
    output = command('systemctl', 'show', NAME, '--all',
                     '--property=' + ','.join(LIVE_UNIT_EXPECTED))
    validate_live_unit_state(output)
    require(not os.path.lexists(RUNTIME), 'existing runtime directory: inspect before testing')
    print('M2.7 installed unit preflight: PASS (loaded, inactive, disabled, no overrides/reload; runtime absent)')


def protected(path: Path, uid: int, gid: int, mode: int, kind) -> None:
    s = path.lstat()
    require(kind(s.st_mode) and s.st_uid == uid and s.st_gid == gid and
            stat.S_IMODE(s.st_mode) == mode, 'unexpected protected file metadata: ' + path.name)


def digest(path: Path) -> bytes:
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').digest()


def installed(binary: Path) -> tuple[int, int]:
    account = pwd.getpwnam('knetsentry')
    group = grp.getgrnam('knetsentry')
    uid, gid = account.pw_uid, account.pw_gid
    require(uid != 0 and gid != 0 and gid == group.gr_gid and
            account.pw_shell == '/usr/sbin/nologin' and account.pw_dir == '/nonexistent' and
            set(os.getgrouplist(account.pw_name, gid)) == {gid}, 'unsafe service account')
    unit_preflight()
    fragment = Path(LIVE_UNIT_EXPECTED['FragmentPath'])
    for path, src, mode in ((fragment, UNIT, 0o644),
                            (INSTALL / 'manager-launcher', UNIT.parent / 'manager-launcher', 0o755),
                            (INSTALL / 'knetsentryd', binary, 0o755)):
        protected(path, 0, 0, mode, stat.S_ISREG)
        if digest(path) != digest(src):
            message = 'installed file differs from tested revision: ' + path.name
            if path == INSTALL / 'knetsentryd':
                message += ('; rebuild Release and explicitly refresh the inactive, disabled '
                            'development binary (see docs/development/SYSTEMD_SERVICE_M27.md)')
            raise ValueError(message)
        for parent in path.parents:
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
                    not info.st_mode & 0o022, 'unsafe installed parent: ' + parent.name)
    return uid, gid


def wait_ready() -> int:
    until = time.monotonic() + 10
    while time.monotonic() < until:
        if prop('ActiveState') == 'active' and SOCKET.is_socket():
            pid = int(prop('MainPID'))
            if pid > 0 and Path(f'/proc/{pid}/exe').resolve() == INSTALL / 'knetsentryd':
                return pid
        time.sleep(0.1)
    raise ValueError('manager readiness timeout')


def check_process(pid: int, uid: int, gid: int) -> None:
    proc = Path(f'/proc/{pid}')
    status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
    require(set(status['Uid'].split()) == {str(uid)} and set(status['Gid'].split()) == {str(gid)},
            'unexpected process identity')
    require(set(status['Groups'].split()) <= {str(gid)}, 'unexpected supplementary groups')
    for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
        require(int(status[key].strip(), 16) == 0, 'nonempty ' + key)
    require(status['NoNewPrivs'].strip() == '1' and status['Seccomp'].strip() == '2',
            'missing kernel privilege/seccomp controls')
    require(os.readlink(proc / 'ns/net') != os.readlink('/proc/1/ns/net') and
            os.readlink(proc / 'ns/mnt') != os.readlink('/proc/1/ns/mnt'), 'namespace isolation missing')
    mounts = {fields[4]: fields[5].split(',') for line in (proc / 'mountinfo').read_text().splitlines()
              if len(fields := line.split()) > 6}
    require('ro' in mounts.get('/', []) and 'rw' in mounts.get(str(STATE), []) and
            'rw' in mounts.get(str(RUNTIME), []), 'unexpected root/state/runtime mount permissions')
    limits = (proc / 'limits').read_text().splitlines()
    require(any(line.split()[3:5] == ['64', '64'] for line in limits if line.startswith('Max open files')),
            'file descriptor limit missing')
    require(any(line.split()[4:6] == ['0', '0'] for line in limits if line.startswith('Max core file size')),
            'core limit missing')
    cgroup = Path('/sys/fs/cgroup') / prop('ControlGroup').lstrip('/')
    require((cgroup / 'memory.max').read_text().strip() == str(128 * 1024 * 1024), 'memory limit missing')
    require((cgroup / 'pids.max').read_text().strip() == '16', 'task limit missing')
    quota, period = (cgroup / 'cpu.max').read_text().split()
    require(quota != 'max' and int(quota) * 4 == int(period), 'CPU quota missing')
    print('M2.7 live identity, empty capabilities, no-new-privileges, seccomp, namespaces, mounts and limits: PASS')


def run(binary: Path, outsider: str) -> None:
    require(os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd',
            'live test requires administrator on a systemd-booted host')
    uid, gid = installed(binary)
    other = pwd.getpwnam(outsider)
    require(other.pw_uid not in {0, uid}, 'outsider must be a distinct ordinary user')
    require(not os.path.lexists(RUNTIME), 'existing runtime directory: inspect before testing')
    if os.path.lexists(STATE):
        protected(STATE, uid, gid, 0o700, stat.S_ISDIR)
    before = set(STATE.glob('session.*')) if STATE.exists() else set()
    # Only stop a service this test attempted to start; caller must ensure no
    # concurrent administrator or automation is managing this dedicated unit.
    try:
        command('systemctl', 'start', NAME)
        pid = wait_ready()
        check_process(pid, uid, gid)
        protected(STATE, uid, gid, 0o700, stat.S_ISDIR)
        protected(RUNTIME, uid, gid, 0o700, stat.S_ISDIR)
        protected(SOCKET, uid, gid, 0o600, stat.S_ISSOCK)
        command('runuser', '-u', 'knetsentry', '--', '/usr/bin/python3', '-I', '-c', QUERY)
        command('runuser', '-u', outsider, '--', '/usr/bin/python3', '-I', '-c', DENY)
        print('M2.7 authorized health and ordinary-user filesystem denial: PASS')
    finally:
        command('systemctl', 'stop', NAME)
    require(prop('Result') == 'success' and prop('ExecMainStatus') == '0' and
            not SOCKET.exists(), 'graceful stop or socket cleanup failed')
    fresh = set(STATE.glob('session.*')) - before
    require(len(fresh) == 1, 'expected exactly one fresh audit session')
    session = fresh.pop()
    protected(session, uid, gid, 0o700, stat.S_ISDIR)
    audit = session / 'service-audit.jsonl'
    protected(audit, uid, gid, 0o600, stat.S_ISREG)
    require(0 < audit.stat().st_size <= 1024 * 1024, 'audit size invalid')
    records = [json.loads(line) for line in audit.read_bytes().splitlines()]
    require([r['event'] for r in records] == ['manager_starting', 'configuration_default', 'ipc_ready',
            'manager_ready', 'health_authorized', 'manager_stopping', 'manager_stopped'], 'audit sequence invalid')
    require(all(r['service_uid'] == uid and r['service_gid'] == gid and r['sequence'] == i
                for i, r in enumerate(records, 1)), 'audit attribution/order invalid')
    require(records[4]['peer'] is not None and records[4]['peer']['uid'] == uid and
            records[4]['peer']['gid'] == gid and len({r['session'] for r in records}) == 1,
            'audit peer/session attribution invalid')
    print('M2.7 graceful systemd stop, socket cleanup, private persisted audit: PASS')
    print('M2.7 installed systemd runtime: PASS (no private audit records printed)')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight-only', action='store_true', help='read-only host state check; no service activation')
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--outsider')
    args = parser.parse_args()
    if args.preflight_only and (args.binary is not None or args.outsider is not None):
        parser.error('--preflight-only does not accept --binary or --outsider')
    if not args.preflight_only and (args.binary is None or not args.outsider):
        parser.error('live test requires --binary and --outsider')
    try:
        if args.preflight_only:
            unit_preflight()
        else:
            run(args.binary.resolve(), args.outsider)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('M2.7 live systemd: FAIL: ' + str(exc))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

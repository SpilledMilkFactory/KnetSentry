#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Explicit administrator-only, disposable dual-namespace TCP policy fixture."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import pwd
import select
import signal
import socket
import subprocess
import sys
import time

IP = '/usr/sbin/ip'
NFT = '/usr/sbin/nft'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
TABLE = 'knetsentry_m36_test'
PORT = 37443
PEERS = ('192.0.2.2', '192.0.2.3', '2001:db8:36::2', '2001:db8:36::3')
CASES = tuple((address, port, address in (PEERS[0], PEERS[2]) and port == PORT)
              for address in PEERS for port in (PORT, PORT + 1))
TOKEN = b'ks36'


def require(condition, label):
    if not condition:
        raise RuntimeError(label)


def command(args, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True,
                            env=ENV, timeout=10, check=True)
    return result.stdout


def ns_id(pid='self'):
    info = os.stat(f'/proc/{pid}/ns/net')
    return info.st_dev, info.st_ino


def inventory():
    return {link['ifname'] for link in json.loads(command([IP, '-j', 'link', 'show']))}


def enter_namespace():
    original = ns_id()
    os.unshare(os.CLONE_NEWNET)
    require(ns_id() != original, 'namespace entry did not change identity')
    require(inventory() == {'lo'}, 'initial interface inventory is not isolated')
    return original


def no_default():
    for family in ('-4', '-6'):
        require(json.loads(command([IP, '-j', family, 'route', 'show', 'default'])) == [],
                'unexpected default route')


def configure(name, addresses):
    command([IP, 'link', 'set', 'dev', name, 'addrgenmode', 'none'])
    for address in addresses:
        ipv6 = ':' in address
        command([IP, '-6' if ipv6 else '-4', 'address', 'add', address, 'dev', name]
                + (['nodad'] if ipv6 else []))
    command([IP, 'link', 'set', 'dev', name, 'up'])
    no_default()
    require(inventory() == {'lo', name}, 'unexpected fixture interface')


def rules(uid):
    require(type(uid) is int and 0 < uid < 4294967295, 'invalid fixture UID')
    return (f'create table inet {TABLE}\n'
            f'create chain inet {TABLE} out {{ type filter hook output priority 0; policy accept; }}\n'
            f'add rule inet {TABLE} out meta skuid {uid} oifname "ks36a" '
            f'ip daddr {PEERS[0]} tcp dport {PORT} counter accept\n'
            f'add rule inet {TABLE} out meta skuid {uid} oifname "ks36a" '
            f'ip6 daddr {PEERS[2]} tcp dport {PORT} counter accept\n'
            f'add rule inet {TABLE} out meta skuid {uid} counter drop\n')


def counters():
    data = json.loads(command([NFT, '-j', '-n', 'list', 'table', 'inet', TABLE]))
    entries = [item['rule']['expr'] for item in data['nftables'] if 'rule' in item]
    require(len(entries) == 3, 'unexpected fixture rule inventory')
    counts = []
    for expr, verdict in zip(entries, ('accept', 'accept', 'drop'), strict=True):
        require(expr[-1] == {verdict: None} and 'counter' in expr[-2], 'unexpected rule verdict')
        count = expr[-2]['counter']['packets']
        require(type(count) is int and count >= 0, 'invalid packet count')
        counts.append(count)
    return counts


def drop_credentials(uid, gid):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    require(os.getuid() == os.geteuid() == uid and os.getgid() == os.getegid() == gid
            and not os.getgroups(), 'fixture credential transition failed')


def peer(control, uid, gid):
    enter_namespace()
    control.sendall(b'N')
    require(control.recv(1) == b'G', 'peer configuration not authorized')
    configure('ks36b', ('192.0.2.2/24', '192.0.2.3/24',
                         '2001:db8:36::2/64', '2001:db8:36::3/64'))
    drop_credentials(uid, gid)
    with ExitStack() as stack:
        listeners = []
        for address, port, _ in CASES:
            listener = stack.enter_context(socket.socket(
                socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM))
            listener.bind((address, port))
            listener.listen(4)
            listeners.append(listener)
        control.sendall(b'R')
        while True:
            ready, _, _ = select.select([control, *listeners], [], [], 20)
            require(bool(ready), 'peer idle deadline')
            if control in ready:
                require(control.recv(1) == b'X', 'peer control interrupted')
                return
            for listener in ready:
                client, _ = listener.accept()
                with client:
                    client.settimeout(1)
                    # Bounded exact echo; never accepts arbitrary commands.
                    message = client.recv(len(TOKEN), socket.MSG_WAITALL)
                    require(message == TOKEN, 'unexpected fixture payload')
                    client.sendall(TOKEN)


PROBE = '''import os, socket, sys
address, port, uid, gid = sys.argv[1:]
assert os.getuid() == os.geteuid() == int(uid)
assert os.getgid() == os.getegid() == int(gid) and not os.getgroups()
with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(1)
    try:
        s.connect((address, int(port)))
    except (TimeoutError, PermissionError):
        sys.exit(3)
    s.sendall(b'ks36')
    assert s.recv(4, socket.MSG_WAITALL) == b'ks36'
'''


def probe(address, port, uid, gid, allowed):
    require(any((address, port) == case[:2] for case in CASES), 'nonfixture endpoint')
    result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', PROBE, address,
                             str(port), str(uid), str(gid)], user=uid, group=gid,
                            extra_groups=[], close_fds=True, env=ENV, capture_output=True,
                            timeout=4, check=False)
    require(result.returncode == (0 if allowed else 3), 'unexpected TCP probe result')


def check_invalidation(binary, uid, gid):
    with subprocess.Popen([str(binary), '--watch'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, user=uid, group=gid, extra_groups=[],
                          close_fds=True, env=ENV) as watcher:
        try:
            require(bool(select.select([watcher.stdout], [], [], 5)[0]) and
                    watcher.stdout.readline() == b'READY\n', 'watcher did not become ready')
            command([IP, 'link', 'set', 'dev', 'ks36a', 'down'])
            watcher.communicate(input=b'\n', timeout=5)
            require(watcher.returncode == 0, 'topology change did not revoke fixture authority')
        finally:
            if watcher.poll() is None:
                watcher.kill()
                watcher.wait(timeout=5)


def wait_peer(pid):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        ended, status = os.waitpid(pid, os.WNOHANG)
        if ended:
            return status
        time.sleep(0.02)
    raise RuntimeError('peer shutdown deadline')


def execute(binary):
    require(os.geteuid() == 0, 'requires explicit administrator execution')
    require(Path(IP).is_file() and Path(NFT).is_file(), 'install iproute2 and nftables')
    uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
    require(uid > 0 and gid > 0 and pwd.getpwuid(uid).pw_gid == gid, 'ordinary sudo caller required')
    service, control = pwd.getpwnam('knetsentry'), pwd.getpwnam('nobody')
    require(service.pw_uid > 0 and control.pw_uid > 0 and service.pw_uid != control.pw_uid
            and uid != service.pw_uid, 'distinct unprivileged fixture identities required')
    require(service.pw_gid > 0 and control.pw_gid > 0 and
            service.pw_dir == '/nonexistent' and service.pw_shell == '/usr/sbin/nologin',
            'invalid fixture service account')
    original = enter_namespace()
    require(all(set(item) == {'metainfo'} for item in
                json.loads(command([NFT, '-j', 'list', 'tables']))['nftables']), 'initial firewall not empty')
    parent, child = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            child.settimeout(15)
            peer(child, control.pw_uid, control.pw_gid)
        except Exception as exc:
            print('M3.6 peer: FAIL:', str(exc)[:160], file=sys.stderr, flush=True)
            os._exit(1)
        os._exit(0)
    child.close()
    reaped = False
    try:
        parent.settimeout(15)
        require(parent.recv(1) == b'N', 'peer namespace not ready')
        require(ns_id(pid) not in (original, ns_id()), 'peer namespace not independent')
        command([IP, 'link', 'add', 'ks36a', 'type', 'veth', 'peer', 'name', 'ks36b'])
        command([IP, 'link', 'set', 'dev', 'ks36b', 'netns', str(pid)])
        configure('ks36a', ('192.0.2.1/24', '2001:db8:36::1/64'))
        parent.sendall(b'G')
        require(parent.recv(1) == b'R', 'peer listeners not ready')
        print('M3.6 two isolated namespaces and veth: ENTERED', flush=True)
        # Never execute repository-built C++ as root.
        subprocess.run([str(binary), '--live'], user=uid, group=gid, extra_groups=[],
                       close_fds=True, env=ENV, timeout=10, check=True)
        for address, port, _ in CASES:
            probe(address, port, service.pw_uid, service.pw_gid, True)
        print('M3.6 all eight dual-stack TCP baseline endpoints: PASS', flush=True)
        profile = rules(service.pw_uid)
        command([NFT, '-c', '-f', '-'], profile)
        command([NFT, '-f', '-'], profile)
        for address, port, allowed in CASES:
            before = counters()
            probe(address, port, service.pw_uid, service.pw_gid, allowed)
            after = counters()
            selected = (1 if ':' in address else 0) if allowed else 2
            # Delayed TCP teardown can increment an earlier allow counter.
            # Require the expected rule to advance; do not assert quiescence.
            require(after[selected] > before[selected], 'expected firewall counter did not advance')
            probe(address, port, control.pw_uid, control.pw_gid, True)
        print('M3.6 scoped test-only TCP allow/deny and control UID: PASS', flush=True)
        command([NFT, 'delete', 'table', 'inet', TABLE])
        require(all(set(item) == {'metainfo'} for item in
                    json.loads(command([NFT, '-j', 'list', 'tables']))['nftables']), 'rollback incomplete')
        for address, port, _ in CASES:
            probe(address, port, service.pw_uid, service.pw_gid, True)
        check_invalidation(binary, uid, gid)
        print('M3.6 live link-change authorization withdrawal: PASS', flush=True)
        parent.sendall(b'X')
        status = wait_peer(pid)
        reaped = True
        require(os.waitstatus_to_exitcode(status) == 0, 'peer did not exit cleanly')
        print('M3.6 rollback, restored delivery and peer cleanup: PASS', flush=True)
    finally:
        parent.close()
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
    print('M3.6 isolated network fixture: COMPLETED', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    args = parser.parse_args()
    try:
        binary = args.binary.resolve(strict=True)
        require(binary.is_file() and os.access(binary, os.X_OK), 'compiled fixture required')
        execute(binary)
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print('M3.6 isolated fixture: FAIL:', str(exc)[:200], file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

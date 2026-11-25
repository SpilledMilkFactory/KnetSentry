#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Explicit administrator-only, disposable dual-namespace M3.6/M3.7 fixture."""
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
# Additional reachable, unapproved subnets (no gateway or external link).
EXTRA_CASES = (('203.0.113.2', PORT, False), ('2001:db8:38::2', PORT, False))
UDP_CASES = tuple((address, PORT) for address in (PEERS[0], PEERS[2],
                  EXTRA_CASES[0][0], EXTRA_CASES[1][0]))
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
                         '2001:db8:36::2/64', '2001:db8:36::3/64',
                         '203.0.113.2/24', '2001:db8:38::2/64'))
    drop_credentials(uid, gid)
    with ExitStack() as stack:
        listeners = []
        for address, port, _ in CASES + EXTRA_CASES:
            listener = stack.enter_context(socket.socket(
                socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM))
            listener.bind((address, port))
            listener.listen(4)
            listeners.append(listener)
        datagrams = []
        for address, port in UDP_CASES:
            listener = stack.enter_context(socket.socket(
                socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM))
            listener.bind((address, port))
            datagrams.append(listener)
        control.sendall(b'R')
        while True:
            ready, _, _ = select.select([control, *listeners, *datagrams], [], [], 20)
            require(bool(ready), 'peer idle deadline')
            if control in ready:
                require(control.recv(1) == b'X', 'peer control interrupted')
                return
            for listener in ready:
                if listener in datagrams:
                    message, sender = listener.recvfrom(len(TOKEN) + 1)
                    require(message == TOKEN, 'unexpected fixture datagram')
                    listener.sendto(TOKEN, sender)
                    continue
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
    require(any((address, port) == case[:2] for case in CASES + EXTRA_CASES), 'nonfixture endpoint')
    result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', PROBE, address,
                             str(port), str(uid), str(gid)], user=uid, group=gid,
                            extra_groups=[], close_fds=True, env=ENV, capture_output=True,
                            timeout=4, check=False)
    require(result.returncode == (0 if allowed else 3), 'unexpected TCP probe result')


UDP_PROBE = '''import os, socket, sys
address, port, uid, gid = sys.argv[1:]
assert os.getuid() == os.geteuid() == int(uid)
assert os.getgid() == os.getegid() == int(gid) and not os.getgroups()
with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(1)
    s.connect((address, int(port)))
    try:
        s.sendall(b'ks36')
    except PermissionError:
        sys.exit(3)  # Linux local-output drop may return EPERM.
    try:
        message = s.recv(5)
    except TimeoutError:
        sys.exit(3)
    assert message == b'ks36'
'''


def udp_probe(address, port, uid, gid, allowed):
    require((address, port) in UDP_CASES, 'nonfixture UDP endpoint')
    result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', UDP_PROBE, address,
                             str(port), str(uid), str(gid)], user=uid, group=gid,
                            extra_groups=[], close_fds=True, env=ENV, capture_output=True,
                            timeout=4, check=False)
    require(result.returncode == (0 if allowed else 3), f'unexpected UDP probe result for {address}:{port} (exit {result.returncode})')


def run_binary(binary, uid, gid, mode):
    subprocess.run([str(binary), mode], user=uid, group=gid, extra_groups=[],
                   close_fds=True, env=ENV, timeout=10, check=True)


def check_restoration(binary, uid, gid, scenario):
    # Fixed commands only, called inside the already verified sender namespace.
    mutations = {
        'ipv4': ([IP, '-4', 'route', 'add', 'blackhole', '192.0.2.2/32'],
                 [IP, '-4', 'route', 'del', 'blackhole', '192.0.2.2/32'], '--route-denied-v4'),
        'ipv6': ([IP, '-6', 'route', 'add', 'blackhole', '2001:db8:36::2/128'],
                 [IP, '-6', 'route', 'del', 'blackhole', '2001:db8:36::2/128'], '--route-denied-v6'),
        'link': ([IP, 'link', 'set', 'dev', 'ks36a', 'down'],
                 [IP, 'link', 'set', 'dev', 'ks36a', 'up'], None),
    }
    require(scenario in mutations, 'nonfixture topology mutation')
    change, restore, mode = mutations[scenario]
    with subprocess.Popen([str(binary), '--watch-restoration'], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, user=uid, group=gid,
                          extra_groups=[], close_fds=True, env=ENV) as watcher:
        try:
            require(bool(select.select([watcher.stdout], [], [], 5)[0]) and
                    watcher.stdout.readline() == b'READY\n', 'restoration watcher not ready')
            command(change)
            if mode:
                run_binary(binary, uid, gid, mode)
            watcher.stdin.write(b'\n')
            watcher.stdin.flush()
            require(bool(select.select([watcher.stdout], [], [], 5)[0]) and
                    watcher.stdout.readline() == b'INVALIDATED\n', 'change did not invalidate authority')
            command(restore)
            no_default()
            # Same watcher, same generation: undoing the mutation must not rearm it.
            watcher.communicate(input=b'\n', timeout=5)
            require(watcher.returncode == 0, 'restoration rearmed old authority')
        finally:
            if watcher.poll() is None:
                watcher.kill()
                watcher.wait(timeout=5)
    if mode:
        run_binary(binary, uid, gid, '--live')
    print(f'M3.7 {scenario} change and sticky withdrawal after restoration: PASS', flush=True)


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
        configure('ks36a', ('192.0.2.1/24', '2001:db8:36::1/64',
                            '203.0.113.1/24', '2001:db8:38::1/64'))
        parent.sendall(b'G')
        require(parent.recv(1) == b'R', 'peer listeners not ready')
        print('M3.6 two isolated namespaces and veth: ENTERED', flush=True)
        # Never execute repository-built C++ as root.
        subprocess.run([str(binary), '--live'], user=uid, group=gid, extra_groups=[],
                       close_fds=True, env=ENV, timeout=10, check=True)
        for address, port, _ in CASES:
            probe(address, port, service.pw_uid, service.pw_gid, True)
        print('M3.6 all eight dual-stack TCP baseline endpoints: PASS', flush=True)
        for address, port, _ in EXTRA_CASES:
            probe(address, port, service.pw_uid, service.pw_gid, True)
        for address, port in UDP_CASES:
            udp_probe(address, port, service.pw_uid, service.pw_gid, True)
        print('M3.7 additional subnet and UDP baseline delivery: PASS', flush=True)
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
        for address, port, _ in EXTRA_CASES:
            before = counters()
            probe(address, port, service.pw_uid, service.pw_gid, False)
            require(counters()[2] > before[2], 'additional subnet drop counter did not advance')
            probe(address, port, control.pw_uid, control.pw_gid, True)
        for address, port in UDP_CASES:
            before = counters()
            udp_probe(address, port, service.pw_uid, service.pw_gid, False)
            require(counters()[2] > before[2], 'UDP drop counter did not advance')
            udp_probe(address, port, control.pw_uid, control.pw_gid, True)
        print('M3.7 additional subnet TCP and unexpected dual-stack UDP denial: PASS', flush=True)
        command([NFT, 'delete', 'table', 'inet', TABLE])
        require(all(set(item) == {'metainfo'} for item in
                    json.loads(command([NFT, '-j', 'list', 'tables']))['nftables']), 'rollback incomplete')
        for address, port, _ in CASES:
            probe(address, port, service.pw_uid, service.pw_gid, True)
        for address, port, _ in EXTRA_CASES:
            probe(address, port, service.pw_uid, service.pw_gid, True)
        for address, port in UDP_CASES:
            udp_probe(address, port, service.pw_uid, service.pw_gid, True)
        print('M3.7 additional subnet and UDP restored after rollback: PASS', flush=True)
        for scenario in ('ipv4', 'ipv6', 'link'):
            print(f'M3.7 topology scenario: {scenario}', flush=True)
            check_restoration(binary, uid, gid, scenario)
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
    print('M3.7 adversarial live fixture: COMPLETED', flush=True)
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

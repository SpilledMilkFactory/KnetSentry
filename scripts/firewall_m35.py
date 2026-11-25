#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Render/inspect the lifecycle-only nftables profile; isolated live test is opt-in."""
import argparse
import json
import os
from pathlib import Path
import pwd
import grp
import socket
import subprocess
import sys

TABLE = 'knetsentry_m35'
CHAIN = 'manager_output'
NFT = '/usr/sbin/nft'
IP = '/usr/sbin/ip'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
MAX_JSON = 65536


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def validate_uid(uid: int) -> None:
    require(type(uid) is int and 0 < uid < 4294967295, 'invalid dedicated service UID')


def service_identity() -> tuple[int, int]:
    account = pwd.getpwnam('knetsentry')
    group = grp.getgrnam('knetsentry')
    validate_uid(account.pw_uid)
    require(account.pw_gid == group.gr_gid and group.gr_gid > 0 and not group.gr_mem,
            'service group is not dedicated')
    require(account.pw_dir == '/nonexistent' and account.pw_shell == '/usr/sbin/nologin',
            'service account does not match sysusers contract')
    require(pwd.getpwuid(account.pw_uid).pw_name == 'knetsentry', 'ambiguous service UID')
    # Local/NSS enumeration is an additional check, not proof of exclusivity.
    require(all(p.pw_name == 'knetsentry' or p.pw_uid != account.pw_uid
                for p in pwd.getpwall()), 'duplicate service UID')
    return account.pw_uid, group.gr_gid


def render(uid: int) -> str:
    validate_uid(uid)
    return (f'create table inet {TABLE}\n'
            f'create chain inet {TABLE} {CHAIN} '
            '{ type filter hook output priority 0; policy accept; }\n'
            f'add rule inet {TABLE} {CHAIN} meta skuid {uid} counter drop\n')


def unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON member')
        result[key] = value
    return result


def verify(raw: str, uid: int) -> int:
    """Require exactly the expected table, base chain, UID match and drop rule."""
    validate_uid(uid)
    require(len(raw.encode('utf-8')) <= MAX_JSON, 'oversized nftables response')
    doc = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(doc, dict) and set(doc) == {'nftables'} and
            isinstance(doc['nftables'], list), 'unexpected nftables response')
    objects = {}
    for entry in doc['nftables']:
        require(isinstance(entry, dict) and len(entry) == 1, 'unexpected nftables object')
        kind, body = next(iter(entry.items()))
        require(kind in {'metainfo', 'table', 'chain', 'rule'} and kind not in objects and
                isinstance(body, dict), 'unexpected or duplicate nftables object')
        objects[kind] = body
    require(set(objects) == {'metainfo', 'table', 'chain', 'rule'}, 'missing nftables object')
    require(type(objects['metainfo'].get('json_schema_version')) is int and
            objects['metainfo']['json_schema_version'] == 1, 'unsupported nft JSON schema')

    def body_without_handle(kind: str) -> dict:
        body = objects[kind].copy()
        if 'handle' in body:
            handle = body.pop('handle')
            require(type(handle) is int and handle > 0, 'invalid object handle')
        return body

    require(body_without_handle('table') == {'family': 'inet', 'name': TABLE},
            'unexpected table properties')
    require(body_without_handle('chain') == {
        'family': 'inet', 'table': TABLE, 'name': CHAIN, 'type': 'filter',
        'hook': 'output', 'prio': 0, 'policy': 'accept'} and
        type(objects['chain']['prio']) is int, 'unexpected base chain')
    rule = body_without_handle('rule')
    expr = rule.pop('expr', None)
    require(rule == {'family': 'inet', 'table': TABLE, 'chain': CHAIN}, 'unexpected rule properties')
    require(isinstance(expr, list) and len(expr) == 3, 'unexpected rule expressions')
    require(expr[0] == {'match': {'op': '==', 'left': {'meta': {'key': 'skuid'}},
                                  'right': uid}} and type(expr[0]['match']['right']) is int,
            'unexpected UID match')
    require(expr[2] == {'drop': None}, 'missing terminal drop')
    require(isinstance(expr[1], dict) and set(expr[1]) == {'counter'} and
            isinstance(expr[1]['counter'], dict), 'missing anonymous counter')
    counter = expr[1]['counter']
    require(set(counter) == {'packets', 'bytes'} and all(
        type(v) is int and 0 <= v < 2**64 for v in counter.values()), 'invalid counter')
    return counter['packets']


def command(args: list[str], *, data: str | None = None, success: bool = True):
    result = subprocess.run(args, input=data, text=True, capture_output=True,
                            env=ENV, timeout=10, check=False)
    require((result.returncode == 0) == success, 'unexpected command outcome: ' + args[0])
    return result.stdout


def snapshot(uid: int) -> int:
    return verify(command([NFT, '-j', '-n', 'list', 'table', 'inet', TABLE]), uid)


# The child creates its own socket after credential transition; it cannot
# inherit the listener or a socket opened with a different UID.
PROBE = '''import os, socket, sys
family, kind, port, uid, gid = map(int, sys.argv[1:])
assert os.getuid() == os.geteuid() == uid
assert os.getgid() == os.getegid() == gid and not os.getgroups()
with socket.socket(family, kind) as s:
    s.settimeout(0.5)
    address = ('127.0.0.1' if family == socket.AF_INET else '::1', port)
    try:
        if kind == socket.SOCK_STREAM:
            s.connect(address)
            s.sendall(b'ks35')
        else:
            s.sendto(b'ks35', address)
    except (PermissionError, TimeoutError):
        sys.exit(3)
'''


def probe(uid: int, gid: int, family: int, kind: int, allowed: bool) -> None:
    with socket.socket(family, kind) as listener:
        listener.settimeout(0.7)
        listener.bind(('127.0.0.1' if family == socket.AF_INET else '::1', 0))
        if kind == socket.SOCK_STREAM:
            listener.listen(1)
        result = subprocess.run(
            ['/usr/bin/python3', '-I', '-B', '-c', PROBE, str(int(family)), str(int(kind)),
             str(listener.getsockname()[1]), str(uid), str(gid)],
            user=uid, group=gid, extra_groups=[], close_fds=True,
            capture_output=True, env=ENV, timeout=4, check=False)
        require(result.returncode in (0, 3), 'probe execution failed')
        received = False
        try:
            if kind == socket.SOCK_STREAM:
                client, _ = listener.accept()
                with client:
                    client.settimeout(0.7)
                    require(client.recv(16) == b'ks35', 'unexpected TCP probe payload')
            else:
                require(listener.recv(16) == b'ks35', 'unexpected UDP probe payload')
            received = True
        except TimeoutError:
            pass
        require(received == allowed, 'unexpected probe delivery')
        if allowed:
            require(result.returncode == 0, 'allowed probe failed')
        elif kind == socket.SOCK_STREAM:
            require(result.returncode == 3, 'blocked TCP probe connected')


def namespace_id() -> tuple[int, int]:
    info = os.stat('/proc/self/ns/net')
    return info.st_dev, info.st_ino


def isolated() -> None:
    require(os.geteuid() == 0, 'isolated live test requires explicit administrator execution')
    require(Path(NFT).is_file() and Path(IP).is_file(), 'install nftables and iproute2 first')
    uid, gid = service_identity()
    outsider = pwd.getpwnam('nobody')
    validate_uid(outsider.pw_uid)
    require(outsider.pw_uid != uid, 'control UID must differ from manager')
    original = namespace_id()
    # This process, not its caller, enters a new disposable net namespace.
    # No mutation is reached unless namespace creation and validation succeed.
    os.unshare(os.CLONE_NEWNET)
    require(namespace_id() != original, 'network namespace did not change')
    links = json.loads(command([IP, '-j', 'link', 'show']))
    require(len(links) == 1 and links[0]['ifname'] == 'lo', 'non-isolated interface inventory')
    initial = json.loads(command([NFT, '-j', 'list', 'tables']))
    require(all(set(item) == {'metainfo'} for item in initial['nftables']),
            'new network namespace has existing firewall tables')
    command([IP, 'link', 'set', 'lo', 'up'])
    print('M3.5 isolated namespace: ENTERED', flush=True)
    unrelated = 'knetsentry_m35_test_unrelated'
    command([NFT, '-f', '-'], data=f'create table inet {unrelated}\n')
    sentinel = command([NFT, '-j', '-n', 'list', 'table', 'inet', unrelated])
    combinations = [(f, k) for f in (socket.AF_INET, socket.AF_INET6)
                    for k in (socket.SOCK_STREAM, socket.SOCK_DGRAM)]
    for family, kind in combinations:
        probe(uid, gid, family, kind, True)
        probe(outsider.pw_uid, outsider.pw_gid, family, kind, True)
    print('M3.5 dual-stack TCP/UDP baseline: PASS', flush=True)
    rules = render(uid)
    command([NFT, '-c', '-f', '-'], data=rules)
    command([NFT, '-f', '-'], data=rules)
    snapshot(uid)
    # A collision must fail, and an invalid atomic batch must leave the
    # original table intact. Neither operation is an automatic replacement.
    command([NFT, '-f', '-'], data=rules, success=False)
    snapshot(uid)
    command([NFT, '-f', '-'], data=f'delete table inet {TABLE}\n'
            'delete table inet knetsentry_m35_missing\n', success=False)
    snapshot(uid)
    print('M3.5 exclusive creation and failed transaction preservation: PASS', flush=True)
    for family, kind in combinations:
        before = snapshot(uid)
        probe(uid, gid, family, kind, False)
        require(snapshot(uid) > before, 'drop counter did not increase')
        before = snapshot(uid)
        probe(outsider.pw_uid, outsider.pw_gid, family, kind, True)
        require(snapshot(uid) == before, 'unrelated UID matched drop rule')
    print('M3.5 dedicated UID IPv4/IPv6 TCP/UDP denial and unrelated UID delivery: PASS', flush=True)
    command([NFT, 'delete', 'table', 'inet', TABLE])
    command([NFT, 'list', 'table', 'inet', TABLE], success=False)
    require(command([NFT, '-j', '-n', 'list', 'table', 'inet', unrelated]) == sentinel,
            'unrelated table changed')
    for family, kind in combinations:
        probe(uid, gid, family, kind, True)
        probe(outsider.pw_uid, outsider.pw_gid, family, kind, True)
    print('M3.5 table-only rollback and restored dual-stack delivery: PASS', flush=True)
    print('M3.5 isolated namespace: COMPLETED', flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('render', 'verify-json', 'live-isolated'))
    args = parser.parse_args()
    try:
        if args.operation == 'live-isolated':
            isolated()
        else:
            uid, _ = service_identity()
            if args.operation == 'render':
                print(render(uid), end='')
            else:
                verify(sys.stdin.read(MAX_JSON + 1), uid)
                print('M3.5 installed table shape: PASS (traffic and other namespaces not verified)')
        return 0
    except (ValueError, KeyError, TypeError, OSError, AttributeError, subprocess.SubprocessError) as exc:
        print('M3.5 firewall: FAIL:', str(exc)[:240], file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

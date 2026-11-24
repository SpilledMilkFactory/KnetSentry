#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Optional actual netlink change regression in a disposable user/net namespace."""
import argparse
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys


def namespace_identity() -> str:
    info = os.stat('/proc/self/ns/net')
    return f'{info.st_dev}:{info.st_ino}'


def inside(binary: Path, original: str) -> None:
    if namespace_identity() == original:
        raise RuntimeError('refusing to change the original network namespace')
    # Use actual netlink inventory, not an inherited sysfs mount.
    ip = shutil.which('ip')
    if ip is None:
        raise RuntimeError('iproute2 is required for this optional test')
    links = subprocess.run([ip, '-j', 'link', 'show'], check=True,
                           capture_output=True, text=True, timeout=5)
    if {link['ifname'] for link in json.loads(links.stdout)} != {'lo'}:
        raise RuntimeError('refusing to change a namespace containing non-loopback interfaces')
    # All commands are fixed synthetic fixtures; no packets are transmitted.
    for label, args in (
        ('link', ['link', 'set', 'lo', 'up']),
        ('IPv4 address', ['-4', 'address', 'add', '192.0.2.1/32', 'dev', 'lo']),
        ('IPv4 route', ['-4', 'route', 'add', '198.51.100.0/24', 'dev', 'lo']),
        ('IPv4 rule', ['-4', 'rule', 'add', 'priority', '12345', 'lookup', '123']),
        ('IPv6 address', ['-6', 'address', 'add', '2001:db8:1::1/128', 'dev', 'lo', 'nodad']),
        ('IPv6 route', ['-6', 'route', 'add', '2001:db8:2::/64', 'dev', 'lo']),
        ('IPv6 rule', ['-6', 'rule', 'add', 'priority', '12345', 'lookup', '123']),
    ):
        with subprocess.Popen([str(binary), '--watch'], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            try:
                if not select.select([child.stdout], [], [], 5)[0] or child.stdout.readline() != b'READY\n':
                    raise RuntimeError(f'{label}: watcher did not become ready')
                subprocess.run([ip, *args], check=True, capture_output=True, timeout=5)
                _, _ = child.communicate(input=b'\n', timeout=5)
                if child.returncode != 0:
                    raise RuntimeError(f'{label}: watcher did not invalidate')
                print(f'M3.3 isolated {label} notification: PASS', flush=True)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
    # Both ends of this synthetic link remain in the disposable namespace.
    for args in (
        ['link', 'add', 'ks33a', 'type', 'veth', 'peer', 'name', 'ks33b'],
        ['link', 'set', 'ks33a', 'up'],
        ['link', 'set', 'ks33b', 'up'],
        ['-4', 'address', 'add', '192.0.2.1/24', 'dev', 'ks33a'],
        ['-6', 'address', 'add', '2001:db8:3::1/64', 'dev', 'ks33a', 'nodad'],
        ['-4', 'route', 'add', 'default', 'dev', 'ks33a'],
        ['-6', 'route', 'add', 'default', 'dev', 'ks33a'],
    ):
        subprocess.run([ip, *args], check=True, capture_output=True, timeout=5)
    inventory = subprocess.run([ip, '-j', 'link', 'show', 'dev', 'ks33a'],
                               check=True, capture_output=True, text=True, timeout=5)
    index = json.loads(inventory.stdout)[0]['ifindex']
    subprocess.run([str(binary), '--namespace-routes', str(index)], check=True, timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--inside', help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        binary = args.binary.resolve(strict=True)
        if args.inside is not None:
            # Do not accept a caller-supplied arbitrary namespace ID as sole
            # evidence: require a distinct namespace and a mapped single UID.
            mapping = Path('/proc/self/uid_map').read_text().split()
            if len(mapping) != 3 or mapping[0] != '0' or mapping[2] != '1' or os.getuid() != 0:
                raise RuntimeError('requires a disposable single-UID user namespace')
            inside(binary, args.inside)
        else:
            if os.geteuid() == 0:
                raise RuntimeError('run as ordinary user, not sudo/root')
            unshare = shutil.which('unshare')
            if unshare is None:
                raise RuntimeError('unshare is required')
            subprocess.run([unshare, '--user', '--map-root-user', '--net', '--',
                            sys.executable, '-B', str(Path(__file__).resolve()),
                            '--binary', str(binary), '--inside', namespace_identity()],
                           check=True, timeout=45)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'M3.3 isolated namespace check: FAIL or BLOCKED ({error})', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

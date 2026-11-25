#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline adversarial fixture contract; no actual network mutations."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import sys

sys.dont_write_bytecode = True
import network_fixture_m36 as fixture

ROOT = Path(__file__).resolve().parent.parent


def reject(action):
    try:
        action()
    except RuntimeError:
        return
    raise AssertionError('unexpected fixture acceptance')


def probe_script_outcomes():
    # Execute the fixed probe program with fake socket and identity only.
    # No live sockets, subprocesses or credential changes in source checks.
    def outcome(send_error=None, receive_error=None, connect_error=None, payload=b'ks36'):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.connect.side_effect = connect_error
        connection.sendall.side_effect = send_error
        connection.recv.side_effect = receive_error
        connection.recv.return_value = payload
        with patch('socket.socket', return_value=connection), \
             patch('os.getuid', return_value=972), patch('os.geteuid', return_value=972), \
             patch('os.getgid', return_value=972), patch('os.getegid', return_value=972), \
             patch('os.getgroups', return_value=[]), \
             patch.object(sys, 'argv', ['probe', '2001:db8:36::2', '37443', '972', '972']):
            try:
                exec(fixture.UDP_PROBE, {})
            except SystemExit as exc:
                return exc.code
            except (OSError, AssertionError):
                return 1
        return 0

    assert outcome() == 0
    assert outcome(send_error=PermissionError()) == 3
    assert outcome(receive_error=TimeoutError()) == 3
    assert outcome(send_error=TimeoutError()) == 1
    assert outcome(connect_error=PermissionError()) == 1
    assert outcome(receive_error=ConnectionRefusedError()) == 1
    assert outcome(payload=b'wrong') == 1


def main():
    probe_script_outcomes()
    assert fixture.EXTRA_CASES == (('203.0.113.2', 37443, False),
                                   ('2001:db8:38::2', 37443, False))
    assert set(fixture.UDP_CASES) == {('192.0.2.2', 37443), ('2001:db8:36::2', 37443),
                                     ('203.0.113.2', 37443), ('2001:db8:38::2', 37443)}
    assert not set(fixture.EXTRA_CASES) & set(fixture.CASES)
    # The original M3.6 firewall rules remain TCP-only; the final drop covers UDP.
    rules = fixture.rules(972).splitlines()
    assert len(rules) == 5 and all('tcp dport' in rule for rule in rules[2:4])
    assert rules[-1].endswith('meta skuid 972 counter drop')
    with patch.object(fixture.subprocess, 'run') as run:
        reject(lambda: fixture.udp_probe('198.51.100.99', 37443, 972, 972, False))
        reject(lambda: fixture.udp_probe('2001:db8:36::2', 37444, 972, 972, False))
        run.assert_not_called()
        for status, allowed in ((0, True), (3, False)):
            run.return_value = SimpleNamespace(returncode=status)
            for address, port in fixture.UDP_CASES:
                fixture.udp_probe(address, port, 972, 972, allowed)
                assert run.call_args.kwargs['user'] == 972
                assert run.call_args.kwargs['group'] == 972
                assert run.call_args.kwargs['extra_groups'] == []
                reject(lambda: fixture.udp_probe(address, port, 972, 972, not allowed))
        for status in (1, 2, -9):
            run.return_value = SimpleNamespace(returncode=status)
            reject(lambda: fixture.udp_probe('2001:db8:36::2', 37443, 972, 972, False))
    with patch.object(fixture.subprocess, 'Popen') as spawn, \
         patch.object(fixture, 'command') as command:
        reject(lambda: fixture.check_restoration(Path('/synthetic'), 1000, 1000, 'other'))
        spawn.assert_not_called()
        command.assert_not_called()
    assert 'NAME knetsentry_network_adversarial_boundary' in (ROOT / 'tests/CMakeLists.txt').read_text()
    assert 'knetsentry_network_adversarial_boundary' in (ROOT / 'scripts/verify_m17_suites.py').read_text()
    print('M3.7 fixed adversarial matrix, credential and failure-classification fixtures: PASS')
    print('M3.7 source-only: live adversarial packet and topology checks NOT verified')


if __name__ == '__main__':
    main()

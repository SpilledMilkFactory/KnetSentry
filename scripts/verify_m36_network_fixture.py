#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline M3.6 fixture safety and matrix contract. No namespace mutations."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import sys

sys.dont_write_bytecode = True
import network_fixture_m36 as fixture

ROOT = Path(__file__).resolve().parent.parent


def reject(action):
    try:
        action()
    except (RuntimeError, PermissionError):
        return
    raise AssertionError('unsafe fixture accepted')


def main():
    assert len(fixture.CASES) == 8 and len(set(fixture.CASES)) == 8
    assert {case[:2] for case in fixture.CASES if case[2]} == {
        ('192.0.2.2', 37443), ('2001:db8:36::2', 37443)}
    profile = fixture.rules(972)
    assert profile.splitlines() == [
        'create table inet knetsentry_m36_test',
        'create chain inet knetsentry_m36_test out { type filter hook output priority 0; policy accept; }',
        'add rule inet knetsentry_m36_test out meta skuid 972 oifname "ks36a" '
        'ip daddr 192.0.2.2 tcp dport 37443 counter accept',
        'add rule inet knetsentry_m36_test out meta skuid 972 oifname "ks36a" '
        'ip6 daddr 2001:db8:36::2 tcp dport 37443 counter accept',
        'add rule inet knetsentry_m36_test out meta skuid 972 counter drop',
    ]
    for bad in (0, -1, 4294967295, True, '972; flush ruleset'):
        reject(lambda: fixture.rules(bad))
    with patch.object(fixture.os, 'unshare', side_effect=PermissionError('fixture')), \
         patch.object(fixture, 'ns_id', return_value=(1, 2)), \
         patch.object(fixture, 'command') as command:
        reject(fixture.enter_namespace)
        command.assert_not_called()
    with patch.object(fixture.os, 'unshare'), \
         patch.object(fixture, 'ns_id', return_value=(1, 2)), \
         patch.object(fixture, 'command') as command:
        reject(fixture.enter_namespace)
        command.assert_not_called()
    with patch.object(fixture.os, 'unshare'), \
         patch.object(fixture, 'ns_id', side_effect=[(1, 2), (1, 3)]), \
         patch.object(fixture, 'inventory', return_value={'lo', 'eth0'}):
        reject(fixture.enter_namespace)
    with patch.object(fixture.os, 'unshare'), \
         patch.object(fixture, 'ns_id', side_effect=[(1, 2), (1, 3)]), \
         patch.object(fixture, 'inventory', return_value={'lo'}):
        assert fixture.enter_namespace() == (1, 2)
    with patch.object(fixture, 'command', return_value='[{"dst":"default"}]'):
        reject(fixture.no_default)
    with patch.object(fixture.subprocess, 'run') as run:
        reject(lambda: fixture.probe('8.8.8.8', 37443, 972, 972, True))
        reject(lambda: fixture.probe('192.0.2.2', 443, 972, 972, True))
        run.assert_not_called()
        for result, allowed in ((0, True), (3, False)):
            run.return_value = SimpleNamespace(returncode=result)
            fixture.probe('192.0.2.2', 37443, 972, 972, allowed)
            assert run.call_args.kwargs['user'] == 972
            assert run.call_args.kwargs['extra_groups'] == []
            reject(lambda: fixture.probe('192.0.2.2', 37443, 972, 972, not allowed))
        run.return_value = SimpleNamespace(returncode=1)
        reject(lambda: fixture.probe('192.0.2.2', 37443, 972, 972, False))
    with patch.object(fixture.os, 'geteuid', return_value=1000), \
         patch.object(fixture, 'enter_namespace') as enter:
        reject(lambda: fixture.execute(Path('/not-used')))
        enter.assert_not_called()
    assert 'NAME knetsentry_network_isolation_fixture' in (ROOT / 'tests/CMakeLists.txt').read_text()
    assert 'knetsentry_network_isolation_fixture' in (ROOT / 'scripts/verify_m17_suites.py').read_text()
    print('M3.6 fixture matrix, isolation guards, probe credentials and outcome fixtures: PASS')
    print('M3.6 source-only: live cross-namespace packet enforcement NOT verified')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Unprivileged M3.5 rule-generation and read-back negative fixtures; no nft calls."""
import copy
import json
from pathlib import Path
import sys
from unittest.mock import patch
from types import SimpleNamespace

sys.dont_write_bytecode = True
import firewall_m35 as fw

ROOT = Path(__file__).resolve().parent.parent
UID = 972


def reject(action) -> None:
    try:
        action()
    except (ValueError, KeyError):
        return
    raise AssertionError('unsafe fixture accepted')


def fixture() -> dict:
    return {'nftables': [
        {'metainfo': {'version': 'fixture', 'json_schema_version': 1}},
        {'table': {'family': 'inet', 'name': fw.TABLE, 'handle': 1}},
        {'chain': {'family': 'inet', 'table': fw.TABLE, 'name': fw.CHAIN,
                   'type': 'filter', 'hook': 'output', 'prio': 0, 'policy': 'accept', 'handle': 2}},
        {'rule': {'family': 'inet', 'table': fw.TABLE, 'chain': fw.CHAIN, 'handle': 3,
                  'expr': [{'match': {'op': '==', 'left': {'meta': {'key': 'skuid'}}, 'right': UID}},
                           {'counter': {'packets': 7, 'bytes': 280}}, {'drop': None}]}}]}


def main() -> None:
    assert fw.render(UID) == ('create table inet knetsentry_m35\n'
                             'create chain inet knetsentry_m35 manager_output '
                             '{ type filter hook output priority 0; policy accept; }\n'
                             'add rule inet knetsentry_m35 manager_output meta skuid 972 counter drop\n')
    for bad in (0, -1, 4294967295, True, 1.5, '972; delete table'):
        reject(lambda: fw.render(bad))
    original = fixture()
    assert fw.verify(json.dumps(original), UID) == 7
    reject(lambda: fw.verify(json.dumps(original), UID + 1))
    reject(lambda: fw.verify(' ' * (fw.MAX_JSON + 1), UID))
    reject(lambda: fw.verify('{"nftables":[],"nftables":[]}', UID))
    for index in range(4):
        mutated = copy.deepcopy(original)
        mutated['nftables'].pop(index)
        reject(lambda: fw.verify(json.dumps(mutated), UID))
    for index, key, value in ((0, 'json_schema_version', 2), (1, 'family', 'ip'),
                              (1, 'flags', ['dormant']), (2, 'hook', 'input'),
                              (2, 'policy', 'drop'), (2, 'prio', 1), (3, 'chain', 'other')):
        mutated = copy.deepcopy(original)
        next(iter(mutated['nftables'][index].values()))[key] = value
        reject(lambda: fw.verify(json.dumps(mutated), UID))
    for expressions in ([{'accept': None}], [{'drop': None}],
                        original['nftables'][3]['rule']['expr'] + [{'accept': None}]):
        mutated = copy.deepcopy(original)
        mutated['nftables'][3]['rule']['expr'] = expressions
        reject(lambda: fw.verify(json.dumps(mutated), UID))
    for key, value in (('op', '!='), ('right', 0), ('right', float(UID)),
                       ('left', {'meta': {'key': 'skgid'}})):
        mutated = copy.deepcopy(original)
        mutated['nftables'][3]['rule']['expr'][0]['match'][key] = value
        reject(lambda: fw.verify(json.dumps(mutated), UID))
    mutated = copy.deepcopy(original)
    mutated['nftables'].append(copy.deepcopy(mutated['nftables'][3]))
    reject(lambda: fw.verify(json.dumps(mutated), UID))
    for bad in (-1, True, 2**64):
        mutated = copy.deepcopy(original)
        mutated['nftables'][3]['rule']['expr'][1]['counter']['packets'] = bad
        reject(lambda: fw.verify(json.dumps(mutated), UID))
    account = SimpleNamespace(pw_uid=UID, pw_gid=UID, pw_name='knetsentry',
                              pw_dir='/nonexistent', pw_shell='/usr/sbin/nologin')
    group = SimpleNamespace(gr_gid=UID, gr_mem=[])
    with patch.object(fw.pwd, 'getpwnam', return_value=account), \
         patch.object(fw.grp, 'getgrnam', return_value=group), \
         patch.object(fw.pwd, 'getpwuid', return_value=account), \
         patch.object(fw.pwd, 'getpwall', return_value=[account]):
        assert fw.service_identity() == (UID, UID)
        group.gr_mem = ['ordinary-user']
        reject(fw.service_identity)
        group.gr_mem = []
        account.pw_uid = 0
        reject(fw.service_identity)
        account.pw_uid = UID
        account.pw_shell = '/bin/bash'
        reject(fw.service_identity)
    # Fail before any mutation if namespace entry fails. No real commands run.
    with patch.object(fw.os, 'geteuid', return_value=0), \
         patch.object(fw.Path, 'is_file', return_value=True), \
         patch.object(fw, 'service_identity', return_value=(UID, UID)), \
         patch.object(fw.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=65534, pw_gid=65534)), \
         patch.object(fw.os, 'unshare', side_effect=PermissionError('fixture')), \
         patch.object(fw, 'command') as command:
        try:
            fw.isolated()
        except PermissionError:
            pass
        else:
            raise AssertionError('namespace failure accepted')
        command.assert_not_called()
    unit = (ROOT / 'packaging/systemd/knetsentry-manager.service').read_text()
    for token in ('User=knetsentry', 'PrivateNetwork=yes', 'RestrictAddressFamilies=AF_UNIX',
                  'CapabilityBoundingSet=\n', 'NoNewPrivileges=yes'):
        assert token in unit
    assert 'NAME knetsentry_firewall_profile_contract' in (ROOT / 'tests/CMakeLists.txt').read_text()
    assert 'FIREWALL_ENFORCEMENT_M35.md' in (ROOT / 'README.md').read_text()
    print('M3.5 rule generation, identity, read-back and isolation negative fixtures: PASS')
    print('M3.5 source-only: live nftables enforcement NOT verified')


if __name__ == '__main__':
    main()

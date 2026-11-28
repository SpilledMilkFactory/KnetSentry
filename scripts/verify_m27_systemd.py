#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Check the exact initial system-service policy; optional systemd parser check."""
from __future__ import annotations

import argparse
import configparser
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
UNIT = ROOT / 'packaging/systemd/knetsentry-manager.service'
EXPECTED = {
    'Type': 'exec', 'User': 'knetsentry', 'Group': 'knetsentry', 'UMask': '0077',
    'RuntimeDirectory': 'knetsentry', 'RuntimeDirectoryMode': '0700',
    'StateDirectory': 'knetsentry', 'StateDirectoryMode': '0700',
    'ExecStart': '/usr/local/libexec/knetsentry/manager-launcher', 'Restart': 'no',
    'TimeoutStartSec': '15s', 'TimeoutStopSec': '10s', 'KillMode': 'control-group',
    'NoNewPrivileges': 'yes', 'CapabilityBoundingSet': '', 'AmbientCapabilities': '',
    'ProtectSystem': 'strict', 'ProtectHome': 'yes', 'PrivateTmp': 'yes',
    'PrivateDevices': 'yes', 'PrivateNetwork': 'yes', 'RestrictAddressFamilies': 'AF_UNIX',
    'ProtectKernelTunables': 'yes', 'ProtectKernelModules': 'yes', 'ProtectKernelLogs': 'yes',
    'ProtectControlGroups': 'yes', 'ProtectClock': 'yes', 'ProtectHostname': 'yes',
    'RestrictNamespaces': 'yes', 'RestrictSUIDSGID': 'yes', 'LockPersonality': 'yes',
    'MemoryDenyWriteExecute': 'yes', 'SystemCallArchitectures': 'native',
    'ProtectProc': 'invisible', 'ProcSubset': 'pid', 'MemoryMax': '128M',
    'TasksMax': '16', 'CPUQuota': '25%', 'LimitNOFILE': '64', 'LimitCORE': '0',
    'StandardOutput': 'journal', 'StandardError': 'journal',
}


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


# Shared by the read-only early preflight and the privileged live verifier.
LIVE_UNIT_EXPECTED = {
    'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'disabled',
    'DropInPaths': '', 'NeedDaemonReload': 'no',
    'FragmentPath': '/etc/systemd/system/knetsentry-manager.service',
}


def validate_live_unit_state(output: str) -> None:
    values = {}
    for line in output.splitlines():
        key, separator, value = line.partition('=')
        require(bool(separator) and key in LIVE_UNIT_EXPECTED and key not in values,
                'malformed or duplicate systemd preflight property')
        values[key] = value
    missing = LIVE_UNIT_EXPECTED.keys() - values.keys()
    require(not missing, 'missing systemd preflight properties: ' + ', '.join(sorted(missing)))
    mismatches = []
    for key, expected in LIVE_UNIT_EXPECTED.items():
        actual = values[key]
        if actual == expected:
            continue
        # Do not disclose arbitrary host paths or override contents in logs.
        if key == 'DropInPaths':
            detail = 'expected empty, got nonempty (overrides present)'
        elif key == 'FragmentPath':
            detail = 'expected dedicated installed unit path, got unexpected or empty path'
        else:
            detail = f'expected {expected!r}, got {actual[:120]!r}'
        mismatches.append(f'{key}: {detail}')
    require(not mismatches, 'installed unit preflight: ' + '; '.join(mismatches))


def live_preflight_contract() -> None:
    good = LIVE_UNIT_EXPECTED.copy()

    def render(values: dict[str, str]) -> str:
        return '\n'.join(f'{key}={value}' for key, value in values.items())

    validate_live_unit_state(render(good))
    validate_live_unit_state(render(dict(reversed(list(good.items())))))
    mutations = {'LoadState': 'not-found', 'ActiveState': 'active', 'UnitFileState': 'enabled',
                 'DropInPaths': '/private/override.conf', 'NeedDaemonReload': 'yes',
                 'FragmentPath': '/private/unit.service'}
    for key, value in mutations.items():
        try:
            validate_live_unit_state(render(dict(good, **{key: value})))
        except ValueError as exc:
            require(key + ':' in str(exc) and '/private/' not in str(exc),
                    'missing or excessively detailed preflight diagnostic')
        else:
            raise ValueError('unsafe live unit state accepted: ' + key)
    for state in ('failed', 'activating', 'deactivating'):
        try:
            validate_live_unit_state(render(dict(good, ActiveState=state)))
        except ValueError:
            pass
        else:
            raise ValueError('unsafe active state accepted: ' + state)
    for bad in (render({k: v for k, v in good.items() if k != 'DropInPaths'}),
                render(good) + '\nActiveState=inactive', render(good) + '\nmalformed', ''):
        try:
            validate_live_unit_state(bad)
        except ValueError:
            pass
        else:
            raise ValueError('incomplete or malformed live unit state accepted')
    try:
        validate_live_unit_state(render(dict(good, ActiveState='active', NeedDaemonReload='yes')))
    except ValueError as exc:
        require('ActiveState:' in str(exc) and 'NeedDaemonReload:' in str(exc),
                'multiple preflight failures not reported')
    else:
        raise ValueError('multiple unsafe live unit states accepted')
    print('M2.7 read-only live preflight state validation and negative controls: PASS')


def validate_unit(text: str) -> None:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string(text)
    require(set(parser.sections()) == {'Unit', 'Service', 'Install'} and not parser.defaults(),
            'unexpected unit sections/defaults')
    require(dict(parser['Service']) == EXPECTED, 'service security policy differs')
    require(dict(parser['Unit']) == {
        'Description': 'KnetSentry management daemon (local lifecycle only)',
        'After': 'local-fs.target'}, 'unexpected unit dependencies')
    require(dict(parser['Install']) == {'WantedBy': 'multi-user.target'}, 'unexpected install policy')


def source_contract() -> None:
    text = UNIT.read_text()
    validate_unit(text)
    for old, new in [('User=knetsentry', 'User=root'), ('NoNewPrivileges=yes', 'NoNewPrivileges=no'),
                     ('CapabilityBoundingSet=', 'CapabilityBoundingSet=CAP_NET_RAW'),
                     ('PrivateNetwork=yes', 'PrivateNetwork=no'), ('Restart=no', 'Restart=always'),
                     ('ProtectSystem=strict', 'ProtectSystem=no'), ('TasksMax=16', 'TasksMax=infinity')]:
        try:
            validate_unit(text.replace(old, new))
        except ValueError:
            continue
        raise ValueError('unsafe unit mutation accepted')
    account = (UNIT.parent / 'knetsentry.conf').read_text()
    require([line for line in account.splitlines() if line and not line.startswith('#')] ==
            ['u knetsentry - "KnetSentry manager" /nonexistent /usr/sbin/nologin'],
            'unexpected service identity policy')
    launcher = UNIT.parent / 'manager-launcher'
    code = launcher.read_text()
    for token in ('set -eu', 'umask 077', '$(id -u)', '$(id -un)', '$(id -gn)',
                  'mktemp -d /var/lib/knetsentry/session.XXXXXXXXXX',
                  'exec /usr/local/libexec/knetsentry/knetsentryd',
                  '--ipc-dir /run/knetsentry --audit-dir "$session"'):
        require(token in code, 'missing launcher contract: ' + token)
    subprocess.run(['/bin/sh', '-n', str(launcher)], check=True, timeout=5)
    print('M2.7 systemd source policy and negative mutations: PASS')
    print('  Source-only: live systemd confinement NOT verified')


def parser_check() -> None:
    # Parser-only check, without installing or starting anything. Substitute an
    # existing executable solely to avoid an uninstalled ExecStart warning.
    with tempfile.TemporaryDirectory(prefix='ks27-unit-') as tmp:
        unit = Path(tmp) / UNIT.name
        unit.write_text(UNIT.read_text().replace(EXPECTED['ExecStart'], '/bin/true'))
        result = subprocess.run(['systemd-analyze', 'verify', str(unit)],
                                capture_output=True, text=True, timeout=30)
        require(result.returncode == 0 and not result.stderr.strip(),
                'systemd parser diagnostics: ' + result.stderr.strip()[:1000])
    print('M2.7 systemd parser (substituted ExecStart, no activation): PASS')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--systemd-parser', action='store_true')
    args = parser.parse_args()
    try:
        source_contract()
        live_preflight_contract()
        if args.systemd_parser:
            parser_check()
    except (OSError, ValueError, configparser.Error, subprocess.SubprocessError) as exc:
        print(f'M2.7 systemd verification: FAIL: {exc}')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

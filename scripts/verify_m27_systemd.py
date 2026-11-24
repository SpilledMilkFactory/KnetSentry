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
        if args.systemd_parser:
            parser_check()
    except (OSError, ValueError, configparser.Error, subprocess.SubprocessError) as exc:
        print(f'M2.7 systemd verification: FAIL: {exc}')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

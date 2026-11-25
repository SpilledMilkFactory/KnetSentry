#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Explicit populated native-journal qualification using an existing offline import tool.
No service activation, network listener, host journal access or private output.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--import-tool', required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    tool = args.import_tool.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='ks-native-journal-') as tmp:
        root = Path(tmp)
        export = root / 'fixture.export'
        journal = root / 'fixture.journal'
        records = []
        for n, unit in ((1, 'fixture.service'), (2, 'excluded.service'), (3, 'fixture.service')):
            records.append(f'__REALTIME_TIMESTAMP={1700000000000000 + n}\n'
                           f'__MONOTONIC_TIMESTAMP={n}\n'
                           '_BOOT_ID=abcdef1234567890abcdef1234567890\n'
                           '_MACHINE_ID=1234567890abcdef1234567890abcdef\n'
                           f'_SYSTEMD_UNIT={unit}\nMESSAGE=private-canary-{n}\n\n')
        export.write_text(''.join(records), encoding='ascii')
        result = subprocess.run([str(tool), '--output=' + str(journal), str(export)],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        if result.returncode != 0 or not journal.is_file():
            raise RuntimeError(f'offline journal import failed: exit={result.returncode}; '
                               f'stderr={len(result.stderr)} bytes')
        subprocess.run([str(binary), str(root)], check=True, timeout=30)
    print('M5.2 populated native journal fixture: PASS (synthetic records only)')


if __name__ == '__main__':
    main()

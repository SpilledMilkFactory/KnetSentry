#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline M5.5 registration and scope; compiled regressions are separate."""
from pathlib import Path
from verify_m17_suites import CORE_TESTS

ROOT = Path(__file__).resolve().parent.parent


def main():
    name = 'knetsentry_telemetry_delivery_contract'
    tests = (ROOT / 'tests/CMakeLists.txt').read_text()
    store = (ROOT / 'src/agent/journal.cpp').read_text()
    receipt = (ROOT / 'src/agent/receipt.cpp').read_text()
    delivery = (ROOT / 'src/agent/delivery.cpp').read_text()
    tls = (ROOT / 'src/core/tls_transport.cpp').read_text()
    if name not in CORE_TESTS or f'NAME {name}' not in tests:
        raise ValueError('missing mandatory M5.5 regression')
    for marker, source in [('telemetry-m55.v1', store), ('telemetry-inbox-m55.v1', receipt),
                           ('backpressured()', store), ('queue_.acknowledge', delivery),
                           ('enrollment::revalidate', delivery), ('telemetry_alpn', tls)]:
        if marker not in source:
            raise ValueError('missing M5.5 control: ' + marker)
    for app in ('manager', 'desktop', 'agent'):
        if 'KnetSentry::AgentDelivery' in (ROOT / f'apps/{app}/CMakeLists.txt').read_text():
            raise ValueError('premature operational delivery linkage')
    if 'TELEMETRY_DELIVERY_M55.md' not in (ROOT / 'docs/README.md').read_text():
        raise ValueError('missing documentation index')
    print('M5.5 protected outbox and offline authenticated delivery registration: PASS (runtime separate)')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Real process policy gating; no real journal source is opened by this test."""
from pathlib import Path
import hashlib
import os
import select
import subprocess
import sys
import tempfile
from fim_m56 import access_guard, cleanup, finish, line, rejection, CONFIG_ERROR, READY


def main():
    binary = sys.argv[1]
    assert os.getuid() != 0
    base = [binary, '--run', '--schema-version', '1', '--collectors']
    with tempfile.TemporaryDirectory(prefix='ks-privacy-', dir='/tmp') as directory:
        root = Path(directory)
        watched = root / 'watched'
        watched.write_bytes(b'synthetic')
        fim = base + ['fim', '--path', str(watched)]
        policy = f'v1;collector=fim;permit=file-content;allow-path={watched}'
        with access_guard(watched):
            rejection(fim, 2, CONFIG_ERROR)
            for bad in ('', 'v2;' + policy[3:], policy + ';', policy + ';unknown=secret',
                        policy + ';permit=file-content', policy + ';collector=fim',
                        policy + ';deny-path=' + str(root), policy + ';deny-path=' + str(watched),
                        policy.replace('permit=file-content;', ''), policy.replace('collector=fim', 'collector=audit'),
                        policy.replace(str(watched), str(root / 'other')), policy + ';permit=auth-message',
                        policy + ';redact=auth-category', policy + ';redact=fim-content', 'v1;' + 'x' * 25000):
                rejection(fim + ['--privacy-policy', bad], 2, CONFIG_ERROR)
        # Prefix boundaries: denying 'watch' does not deny 'watched'.
        redacted = policy + f';deny-path={root / "watch"};redact=fim-slot'
        with subprocess.Popen(fim + ['--privacy-policy', redacted], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0) as proc:
            try:
                line(proc, READY)
                watched.write_bytes(b'changed!!')
                line(proc, b'knetsentry-agent: fim change; kind=content-changed')
                assert not select.select([proc.stdout], [], [], 0.2)[0]
                finish(proc)
            finally:
                cleanup(proc)
        # Content-redacted FIM must not open or read even the approved file.
        metadata = policy.replace('permit=file-content;', '') + ';redact=fim-content;redact=fim-slot'
        with access_guard(watched):
            with subprocess.Popen(fim + ['--privacy-policy', metadata], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0) as proc:
                try:
                    line(proc, b'knetsentry-agent: ready; collectors=1; fim=metadata-only; monitoring=unavailable; network=disabled')
                    watched.chmod(0o400)
                    line(proc, b'knetsentry-agent: fim change; kind=metadata-changed')
                    finish(proc)
                finally:
                    cleanup(proc)
        auth = base + ['authentication', '--unit', 'ssh.service', '--state-dir', str(root / 'missing')]
        ap = 'v1;collector=authentication;allow-unit=ssh.service;permit=journal-identifiers'
        for bad in (ap, ap + ';permit=auth-message;deny-unit=ssh.service',
                    ap + ';permit=auth-message;redact=auth-category', ap + ';redact=unknown',
                    ap.replace('ssh.service', 'sshd.service') + ';permit=auth-message'):
            rejection(auth + ['--privacy-policy', bad], 2, CONFIG_ERROR)
        rejection(auth + ['--privacy-policy', ap + ';redact=auth-category'], 1,
                  b'knetsentry-agent: journal rejected: unsafe or busy state directory\n')
        rejection(auth + ['--buffer-for', 'a' * 96, '--privacy-policy', ap + ';redact=auth-category'], 2, CONFIG_ERROR)
        audit = base + ['audit', '--state-dir', str(root / 'missing')]
        rejection(audit + ['--privacy-policy', 'v1;collector=audit;permit=journal-identifiers'], 2, CONFIG_ERROR)
        rejection(base + ['none', '--privacy-policy', policy], 2, CONFIG_ERROR)
        # Real CLI: stale policy or legacy state rejected before journal access.
        state = root / 'state'
        state.mkdir(mode=0o700)
        binding = 'a' * 96
        buffered = base + ['authentication', '--unit', 'ssh.service', '--state-dir', str(state), '--buffer-for', binding]
        old_policy = ap + ';permit=auth-message;permit=buffering'
        new_policy = ap + ';redact=auth-category;permit=buffering'
        header = f'KNETSENTRY-OUTBOX-V1\t{binding}\tKNETSENTRY-AUTH-V1\tssh.service\n\n'
        path = state / 'telemetry-m55.v1'
        old_hash = hashlib.sha256(old_policy.encode('ascii')).hexdigest()
        for text in (header, 'KNETSENTRY-PRIVACY-V1\t' + old_hash + '\n' + header):
            path.write_text(text, encoding='ascii')
            path.chmod(0o600)
            rejection(buffered + ['--privacy-policy', new_policy], 1,
                      b'knetsentry-agent: journal rejected: invalid or inaccessible state\n')
            assert path.read_text(encoding='ascii') == text
    print('M5.7 mandatory policy, exclusions, sensitive permits, no denied file access, metadata-only FIM, slot redaction and state binding: PASS')


if __name__ == '__main__':
    main()

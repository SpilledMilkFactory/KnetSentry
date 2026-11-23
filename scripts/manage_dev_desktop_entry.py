#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Explicit, reversible per-user GNOME/KDE desktop registration for dev builds.

Never runs automatically as part of builds, tests, or startup.
Never overwrites a file not marked as owned by this development helper.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

APP_ID = "io.github.spilledmilkfactory.KnetSentry"
MARKER = "X-KnetSentry-Dev-Managed=true"
parser = argparse.ArgumentParser(description=__doc__)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--install", action="store_true")
group.add_argument("--check", action="store_true")
group.add_argument("--uninstall", action="store_true")
parser.add_argument("--binary", type=Path, help="Existing built desktop executable for --install")
args = parser.parse_args()
if os.geteuid() == 0:
    parser.error("run as your regular desktop user, not root")
raw_home = os.environ.get("XDG_DATA_HOME", "")
base = Path(raw_home) if raw_home else Path.home() / ".local/share"
if not base.is_absolute():
    parser.error("XDG_DATA_HOME must be an absolute path")
folder = base / "applications"
target = folder / f"{APP_ID}.desktop"
if target.is_symlink():
    parser.error("refusing a symbolic-link desktop entry")
existing = target.read_text(encoding="utf-8") if target.is_file() else ""
managed = MARKER in existing
if args.check:
    if not existing:
        sys.exit("Developer desktop entry is not installed; portal registration may warn")
    if not managed:
        sys.exit("Desktop entry exists but is not managed by KnetSentry helper")
    print(f"KnetSentry development desktop entry: present ({target})")
    sys.exit(0)
if args.uninstall:
    if not existing:
        print("No developer desktop entry to remove")
        sys.exit(0)
    if not managed:
        parser.error("refusing to remove desktop entry not owned by this helper")
    target.unlink()
    print(f"Removed developer desktop entry: {target}")
    sys.exit(0)
if not args.binary:
    parser.error("--install requires --binary")
binary = args.binary.expanduser().resolve(strict=True)
if not binary.is_file() or not os.access(binary, os.X_OK):
    parser.error("--binary must be an executable file")
if any(ch in str(binary) for ch in ('\n', '\r', '"', '\\')):
    parser.error("unsupported characters in binary pathname")
if existing and not managed:
    parser.error("refusing to overwrite existing non-development desktop entry")
content = ("# SPDX-FileCopyrightText: 2026 Chris Sutton\n"
           "# SPDX-License-Identifier: MIT\n"
           "[Desktop Entry]\n"
           "Type=Application\n"
           "Name=KnetSentry (Development)\n"
           "Comment=KnetSentry local desktop development preview\n"
           f'Exec="{binary}"\n'
           "Icon=network-workgroup\n"
           "Terminal=false\n"
           "Categories=System;Monitor;\n"
           "StartupNotify=true\n"
           f"{MARKER}\n")
folder.mkdir(mode=0o700, parents=True, exist_ok=True)
if folder.is_symlink():
    parser.error("refusing symbolic-link applications directory")
# No elevated install. Exclusive creation or explicit replacement of our own
# existing entry; no auto-modification of desktop registration on startup.
if not existing:
    with target.open('x', encoding='utf-8') as stream:
        stream.write(content)
else:
    target.write_text(content, encoding='utf-8')
target.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
print(f"Installed per-user development entry: {target}")
print("Launch the same built executable again to test portal registration.")

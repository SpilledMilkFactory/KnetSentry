#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
# Ubuntu 26.04 CI profile installer. Does not cache/restore privileged APT state.
set -euo pipefail

usage() {
    printf 'Usage: %s <linux-preset|policy|qml> [--list]\n' "$0" >&2
    exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
profile="$1"
[[ $# -eq 1 || "$2" == '--list' ]] || usage

base=(build-essential cmake ninja-build python3 libssl-dev pkg-config libsystemd-dev libsqlite3-dev)
desktop=(
    qt6-base-dev qt6-declarative-dev qt6-declarative-dev-tools
    extra-cmake-modules libkirigami-dev
    qml6-module-org-kde-kirigami qml6-module-qtquick
    qml6-module-qtquick-controls qml6-module-qtquick-layouts
)

case "$profile" in
    linux-core-only|linux-sanitize-core-only)
        packages=("${base[@]}")
        ;;
    linux-release|linux-debug|linux-sanitize|qml)
        packages=("${base[@]}" "${desktop[@]}")
        ;;
    linux-analysis)
        packages=("${base[@]}" "${desktop[@]}" clang-tidy)
        ;;
    linux-clazy)
        packages=("${base[@]}" "${desktop[@]}" clazy libomp-dev)
        ;;
    policy)
        packages=(python3 reuse python3-yaml)
        ;;
    *)
        printf 'unsupported CI dependency profile: %s\n' "$profile" >&2
        exit 2
        ;;
esac

# This mode can be run without elevated privileges on developer machines and
# in offline CI policy tests. It never queries or modifies the APT database.
if [[ "${2:-}" == '--list' ]]; then
    printf '%s\n' "${packages[@]}"
    exit 0
fi

# No unsupported host, including a PR's choice of runner, may silently qualify.
. /etc/os-release
if [[ "$ID" != 'ubuntu' || "$VERSION_ID" != '26.04' || "$(uname -m)" != 'x86_64' ]]; then
    echo 'CI dependency provisioning requires Ubuntu 26.04 x86_64' >&2
    exit 1
fi

missing=()
for package in "${packages[@]}"; do
    if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -qx 'install ok installed'; then
        missing+=("$package")
    fi
done

if (( ${#missing[@]} > 0 )); then
    printf 'CI profile=%s: %s missing packages; installing: %s\n' \
        "$profile" "${#missing[@]}" "${missing[*]}"
    # Refresh only when needed. A fresh GitHub-hosted runner is a new VM;
    # package installs are NOT automatically persisted across jobs/runs.
    sudo apt-get update
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
else
    printf 'CI profile=%s: all %s direct packages are installed; skipping APT refresh and installation\n' \
        "$profile" "${#packages[@]}"
fi

if [[ "$profile" != policy ]]; then
    dpkg-query -W -f='${Package} ${Version}\n' libssl-dev libssl3t64 libsystemd-dev libsystemd0 libsqlite3-dev libsqlite3-0
    for executable in cmake ninja g++ python3 pkg-config; do
        command -v "$executable" >/dev/null || {
            echo "missing required executable: $executable" >&2
            exit 1
        }
    done
fi
if [[ "$profile" == linux-clazy ]]; then
    command -v clazy >/dev/null || { echo 'missing clazy' >&2; exit 1; }
fi
if [[ "$profile" == linux-analysis ]]; then
    command -v clang-tidy >/dev/null || { echo 'missing clang-tidy' >&2; exit 1; }
fi
if [[ "$profile" == policy ]]; then
    command -v reuse >/dev/null || { echo 'missing reuse' >&2; exit 1; }
fi
printf 'CI dependency profile %s: ready\n' "$profile"

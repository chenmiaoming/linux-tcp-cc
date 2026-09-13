#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required=(
  tcpcc-final.config
  tcpcc-enabled.config
  tcpcc-link.env
  tcpcc-vmlinux.size
  tcpcc-vmlinux.sections
  tcpcc-vmlinux.symbols
  tcpcc-vmlinux.top-symbols
  tcpcc-footprint.md
)

for name in "${required[@]}"; do
  if [[ ! -s "$ROOT/.build/$name" ]]; then
    echo "missing footprint artifact: .build/$name" >&2
    exit 1
  fi
done

config_count=$(grep -Ec '^CONFIG_[A-Z0-9_]+=(y|m)$' \
  "$ROOT/.build/tcpcc-final.config")
enabled_count=$(wc -l < "$ROOT/.build/tcpcc-enabled.config")
if (( config_count != enabled_count )); then
  echo "enabled config list mismatch: final=$config_count exported=$enabled_count" >&2
  exit 1
fi

if ! grep -q '^GNU_SIZE_ALLOCATED=' "$ROOT/.build/tcpcc-link.env"; then
  echo "tcpcc-link.env is missing GNU_SIZE_ALLOCATED" >&2
  exit 1
fi
if ! grep -q '^CONFIG_SHA256=' "$ROOT/.build/tcpcc-link.env"; then
  echo "tcpcc-link.env is missing CONFIG_SHA256" >&2
  exit 1
fi
if ! grep -q '^## TCPCC static footprint baseline$' \
  "$ROOT/.build/tcpcc-footprint.md"; then
  echo "footprint markdown header missing" >&2
  exit 1
fi

printf 'TCPCC footprint artifacts are complete and internally consistent\n'

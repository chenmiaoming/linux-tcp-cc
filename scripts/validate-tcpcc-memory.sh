#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOT_LOG="$ROOT/.build/tcpcc-bootstrap.log"

bash "$ROOT/scripts/validate-tcpcc-bootstrap.sh"

grep -F 'tcpcc: M3.1 host memory [0x100000-0x10000000), image reserved through ' \
  "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.1 memblock probe passed at ' "$BOOT_LOG" >/dev/null
grep -F 'Kernel panic - not syncing: tcpcc: M3.1 deterministic stop after memblock bootstrap' \
  "$BOOT_LOG" >/dev/null

if grep -Fq 'tcpcc: host RAM mapping ' "$BOOT_LOG"; then
  echo "host RAM mapping reported a failure" >&2
  exit 1
fi

printf 'M3.1 host-memory/memblock validation succeeded\n'

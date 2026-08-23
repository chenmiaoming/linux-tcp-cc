#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOT_LOG="$ROOT/.build/tcpcc-bootstrap.log"

require_log()
{
  local marker="$1"

  if ! grep -F -- "$marker" "$BOOT_LOG" >/dev/null; then
    printf 'missing M3.1 memory log marker: %s\n' "$marker" >&2
    exit 1
  fi
}

bash "$ROOT/scripts/validate-tcpcc-bootstrap.sh"

# Keep the M3.1 wrapper aligned with the current resource model: the hosted ELF
# image is separate from a fixed 16 MiB [16 MiB, 32 MiB) allocatable RAM arena.
require_log 'tcpcc: M3.1 host RAM [0x1000000-0x2000000), kernel image '
require_log 'tcpcc: M3.1 memblock probe passed at '
require_log 'Kernel panic - not syncing: tcpcc: M3.1 deterministic stop after memblock bootstrap'

if grep -Eq 'tcpcc: host RAM mapping \[[^]]+\) failed:' "$BOOT_LOG"; then
  echo "host RAM mapping reported a failure" >&2
  exit 1
fi

printf 'M3.1 host-memory/memblock validation succeeded\n'

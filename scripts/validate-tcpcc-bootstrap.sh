#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${LINUX_SRC:-$ROOT/.deps/linux}"
OUT="${TCPCC_LINK_OUT:-$ROOT/.build/tcpcc-bootstrap-out}"
BOOT_LOG="$ROOT/.build/tcpcc-bootstrap.log"
ELF_HEADER="$ROOT/.build/tcpcc-vmlinux.elf-header"
ELF_PROGRAM_HEADERS="$ROOT/.build/tcpcc-vmlinux.program-headers"
SYMBOLS="$ROOT/.build/tcpcc-vmlinux.symbols"
EXPECTED_STATUS=86

require_log()
{
  local marker="$1"

  if ! grep -F -- "$marker" "$BOOT_LOG" >/dev/null; then
    printf 'missing bootstrap log marker: %s\n' "$marker" >&2
    exit 1
  fi
}

LINUX_SRC="$SRC" TCPCC_LINK_OUT="$OUT" \
  bash "$ROOT/scripts/validate-tcpcc-link.sh"

# Materialize producer output before grepping it. With `set -o pipefail`, using
# `readelf|grep -q` or `nm|grep -q` can turn a successful early grep match into
# status 141 when the producer receives SIGPIPE.
readelf -hW "$OUT/vmlinux" > "$ELF_HEADER"
readelf -lW "$OUT/vmlinux" > "$ELF_PROGRAM_HEADERS"
nm "$OUT/vmlinux" > "$SYMBOLS"

if ! grep -Eq 'Type:[[:space:]]+EXEC' "$ELF_HEADER"; then
  echo "hosted bootstrap requires an executable ET_EXEC image" >&2
  exit 1
fi
if grep -q 'INTERP' "$ELF_PROGRAM_HEADERS"; then
  echo "hosted vmlinux unexpectedly requires a userspace ELF interpreter" >&2
  exit 1
fi
if ! grep -Eq '[[:space:]]tcpcc_host_start$' "$SYMBOLS"; then
  echo "tcpcc host entry symbol is missing" >&2
  exit 1
fi

rm -f "$BOOT_LOG"
chmod u+x "$OUT/vmlinux"
set +e
timeout 10s "$OUT/vmlinux" >"$BOOT_LOG" 2>&1
boot_status=$?
set -e

cat "$BOOT_LOG"

if (( boot_status != EXPECTED_STATUS )); then
  printf 'expected hosted kernel exit status %d, got %d\n' \
    "$EXPECTED_STATUS" "$boot_status" >&2
  exit 1
fi

require_log 'Linux version 6.18.45'
require_log 'tcpcc: M2.3 reached setup_arch from hosted start_kernel'

# M3.1 must prove that the bounded host RAM arena is distinct from the hosted
# ELF image and that a real upstream memblock allocation can use that arena.
require_log 'tcpcc: M3.1 host RAM [0x1000000-0x2000000), kernel image '
require_log 'tcpcc: M3.1 memblock probe passed at '
require_log 'Kernel panic - not syncing: tcpcc: M3.1 deterministic stop after memblock bootstrap'
require_log 'tcpcc-host: panic boundary -> exit(86)'

LINUX_SRC="$SRC" bash "$ROOT/scripts/verify-protected.sh"
printf 'hosted start_kernel/M3.1 memory bootstrap validation succeeded\n'

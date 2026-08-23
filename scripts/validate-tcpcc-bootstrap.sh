#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${LINUX_SRC:-$ROOT/.deps/linux}"
OUT="${TCPCC_LINK_OUT:-$ROOT/.build/tcpcc-bootstrap-out}"
BOOT_LOG="$ROOT/.build/tcpcc-bootstrap.log"
ELF_PROGRAM_HEADERS="$ROOT/.build/tcpcc-vmlinux.program-headers"
EXPECTED_STATUS=86

LINUX_SRC="$SRC" TCPCC_LINK_OUT="$OUT" \
  bash "$ROOT/scripts/validate-tcpcc-link.sh"

grep -Fx 'CONFIG_HIGH_RES_TIMERS=y' "$OUT/.config" >/dev/null

readelf -lW "$OUT/vmlinux" > "$ELF_PROGRAM_HEADERS"
if ! readelf -hW "$OUT/vmlinux" | grep -Eq 'Type:[[:space:]]+EXEC'; then
  echo "tcpcc requires an executable ET_EXEC hosted image" >&2
  exit 1
fi
if readelf -lW "$OUT/vmlinux" | grep -q 'INTERP'; then
  echo "tcpcc vmlinux unexpectedly requires a userspace ELF interpreter" >&2
  exit 1
fi
if ! nm "$OUT/vmlinux" | grep -Eq '[[:space:]]tcpcc_host_start$'; then
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

grep -F 'Linux version 6.18.45' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.1 host RAM 128 MiB at' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.1 setup_arch memory initialization complete' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.2 host monotonic clocksource active' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.2 host one-shot clockevent registered' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.2 one-shot hrtimer stress passed (32 rounds,' "$BOOT_LOG" >/dev/null
grep -F 'Kernel panic - not syncing: tcpcc: M3.2 reached timer boundary after hrtimer stress' \
  "$BOOT_LOG" >/dev/null
grep -F 'tcpcc-host: panic boundary -> exit(86)' "$BOOT_LOG" >/dev/null

LINUX_SRC="$SRC" bash "$ROOT/scripts/verify-protected.sh"
printf 'M3.2 monotonic clock/one-shot hrtimer validation succeeded\n'

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${LINUX_SRC:-$ROOT/.deps/linux}"
OUT="${TCPCC_LINK_OUT:-$ROOT/.build/tcpcc-bootstrap-out}"
BOOT_LOG="$ROOT/.build/tcpcc-bootstrap.log"
CONTROL_RESPONSES="$ROOT/.build/tcpcc-control.responses"
ELF_PROGRAM_HEADERS="$ROOT/.build/tcpcc-vmlinux.program-headers"
STRACE_LOG="$ROOT/.build/tcpcc-host.strace"

# shellcheck disable=SC1091
source "$ROOT/upstream/linux.env"

LINUX_SRC="$SRC" TCPCC_LINK_OUT="$OUT" \
  bash "$ROOT/scripts/validate-tcpcc-link.sh"

grep -Fx 'CONFIG_HIGH_RES_TIMERS=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_BASE_SMALL=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_PAGE_SIZE_4KB=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_TINY_RCU=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_NET=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_INET=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_TCP_CONG_ADVANCED=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_TCP_CONG_CUBIC=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_TCP_CONG_BBR=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_NET_SCHED=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_NET_SCH_FQ=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_NET_SCH_DEFAULT=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_DEFAULT_FQ=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_DEFAULT_NET_SCH="fq"' "$OUT/.config" >/dev/null

readelf -lW "$OUT/vmlinux" > "$ELF_PROGRAM_HEADERS"
if ! readelf -hW "$OUT/vmlinux" | grep -Eq 'Type:[[:space:]]+EXEC'; then
  echo "tcpcc requires an executable ET_EXEC hosted image" >&2
  exit 1
fi
if readelf -lW "$OUT/vmlinux" | grep -q 'INTERP'; then
  echo "tcpcc vmlinux unexpectedly requires a userspace ELF interpreter" >&2
  exit 1
fi
if ! nm "$OUT/vmlinux" | \
  awk '$NF == "tcpcc_host_start" { found = 1 } END { exit !found }'; then
  echo "tcpcc host entry symbol is missing" >&2
  exit 1
fi
if ! nm "$OUT/vmlinux" | \
  awk '$NF == "tcpcc_switch_context" { found = 1 } END { exit !found }'; then
  echo "tcpcc hosted context-switch primitive is missing" >&2
  exit 1
fi

rm -f "$BOOT_LOG" "$CONTROL_RESPONSES" "$STRACE_LOG" "$STRACE_LOG".*
chmod u+x "$OUT/vmlinux"
strace -ff -ttt -s 256 -o "$STRACE_LOG" \
  python3 "$ROOT/scripts/run-tcpcc-m6-diagnostic.py" \
    --kernel "$OUT/vmlinux" \
    --boot-log "$BOOT_LOG" \
    --responses "$CONTROL_RESPONSES"

cat "$BOOT_LOG"

grep -F "Linux version $LINUX_VERSION" "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.1 host RAM 128 MiB at' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.1 setup_arch memory initialization complete' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.2 host monotonic clocksource active' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.2 host one-shot clockevent registered' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.2 one-shot hrtimer stress passed (32 rounds,' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.3 task-switch stress passed (4 workers x 32 sleep/wake rounds)' \
  "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M3.4 host epoll event loop initialized' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M8.2 host readiness masks passed (write/read/hup and 64-bit token)' \
  "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M8.2 runtime event IRQ passed (bounded queue and generation token)' \
  "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M8.2.3 nonblocking host TCP backend probe passed (192 bytes each direction)' \
  "$BOOT_LOG" >/dev/null
if ! grep -F 'MSG_NOSIGNAL' "$STRACE_LOG".* >/dev/null; then
  echo "M8.2.3 host backend write did not use MSG_NOSIGNAL" >&2
  exit 1
fi
grep -F 'tcpcc: M3.4 IRQ/softirq event-loop stress passed (64 rounds)' \
  "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M4.1 loopback TCP stress starting (16 rounds x 65536 bytes each direction)' \
  "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M4.1 loopback TCP stress passed (16 rounds, 65536 bytes each direction)' \
  "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M4.2 host control bridge ready on stdin/stdout' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M4.2 host control bridge passed native loopback TCP and Reno/CUBIC control' \
  "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M5.1 L3 netdevice tcpcc' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M6.1 root qdisc fq active on tcpcc0' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: TCP send-buffer ceiling ' "$BOOT_LOG" |
  grep -F -- '-> 4194304 bytes (on-demand, tcp_mem-governed)' >/dev/null
grep -F 'tcpcc: M5.1 hosted L3 netdevice passed (' "$BOOT_LOG" >/dev/null
grep -F 'Kernel panic - not syncing: tcpcc: M5.1 reached hosted L3 netdevice boundary after packet-fd validation' \
  "$BOOT_LOG" >/dev/null
grep -F 'tcpcc-host: panic boundary -> exit(86)' "$BOOT_LOG" >/dev/null

if grep -Fq 'tcpcc: M3.2 reached timer boundary after hrtimer stress' "$BOOT_LOG"; then
  echo "hosted boot stopped at the obsolete M3.2 boundary" >&2
  exit 1
fi
if grep -Fq 'tcpcc: M3.3 reached task-switch boundary after scheduler stress' "$BOOT_LOG"; then
  echo "hosted boot stopped at the obsolete M3.3 boundary" >&2
  exit 1
fi
if grep -Fq 'tcpcc: M3.4 reached event-loop boundary after IRQ/softirq stress' "$BOOT_LOG"; then
  echo "hosted boot stopped at the obsolete M3.4 boundary" >&2
  exit 1
fi
if grep -Fq 'tcpcc: M4.1 reached loopback TCP boundary after in-runtime transfer stress' "$BOOT_LOG"; then
  echo "hosted boot stopped at the obsolete M4.1 boundary" >&2
  exit 1
fi
if grep -Fq 'tcpcc: M4.2 reached userspace control boundary after native TCP/CC validation' "$BOOT_LOG"; then
  echo "hosted boot stopped at the obsolete M4.2 boundary" >&2
  exit 1
fi

LINUX_SRC="$SRC" bash "$ROOT/scripts/verify-protected.sh"
printf 'M6.1 hosted native BBR/default-fq configuration and packet-fd validation succeeded\n'

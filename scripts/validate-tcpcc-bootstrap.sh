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
grep -Fx 'CONFIG_NO_HZ_IDLE=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_NO_HZ_COMMON=y' "$OUT/.config" >/dev/null
grep -Fx 'CONFIG_TICK_ONESHOT=y' "$OUT/.config" >/dev/null
grep -Fx '# CONFIG_HZ_PERIODIC is not set' "$OUT/.config" >/dev/null
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

assert_tcp_mem_budget_raised() {
  local boot_log="$1"
  local line
  local old_pressure
  local new_pressure

  line="$(grep -F 'tcpcc: TCP memory budget ' "$boot_log" | tail -n 1)"
  printf '%s\n' "$line" |
    grep -F 'send-buffer coordinated, pressure cap 12.5% hosted RAM' >/dev/null
  old_pressure="$(printf '%s\n' "$line" |
    sed -E 's/.*TCP memory budget [0-9]+\/([0-9]+)\/[0-9]+ ->.*/\1/')"
  new_pressure="$(printf '%s\n' "$line" |
    sed -E 's/.*-> [0-9]+\/([0-9]+)\/[0-9]+ pages.*/\1/')"
  if [[ ! "$old_pressure" =~ ^[0-9]+$ || ! "$new_pressure" =~ ^[0-9]+$ ||
        "$new_pressure" -le "$old_pressure" ]]; then
    echo "tcpcc tcp_mem pressure budget was not raised: $line" >&2
    exit 1
  fi
}

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
grep -F 'tcpcc: M11 L3 netdevice tcpcc' "$BOOT_LOG" |
  grep -F 'single budgeted event pump' >/dev/null
grep -F 'tcpcc: M6.1 root qdisc fq active on tcpcc0' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: TCP send-buffer ceiling ' "$BOOT_LOG" |
  grep -F -- '-> 2097152 bytes (auto, hosted RAM 126 MiB, on-demand, tcp_mem-governed)' >/dev/null
assert_tcp_mem_budget_raised "$BOOT_LOG"
grep -F 'tcpcc: TCP memory policy ram_pages=' "$BOOT_LOG" |
  grep -F ' tcp_mem=' |
  grep -F ' tcp_wmem=' |
  grep -F ' pressure=' >/dev/null
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

run_memory_profile() {
  local label="$1"
  local memory_mib="$2"
  local tcp_wmem_kib="$3"
  local expected_bytes="$4"
  local expected_policy="$5"
  local wrapper="$ROOT/.build/tcpcc-${label}-kernel.sh"
  local boot_log="$ROOT/.build/tcpcc-${label}-bootstrap.log"
  local responses="$ROOT/.build/tcpcc-${label}-control.responses"

  cat >"$wrapper" <<EOF
#!/bin/sh
exec "$OUT/vmlinux" --memory-mib=$memory_mib --tcp-wmem-max-kib=$tcp_wmem_kib "\$@"
EOF
  chmod u+x "$wrapper"
  python3 "$ROOT/scripts/run-tcpcc-m6-diagnostic.py" \
    --kernel "$wrapper" \
    --boot-log "$boot_log" \
    --responses "$responses"
  grep -F "tcpcc: M3.1 host RAM $memory_mib MiB at" "$boot_log" >/dev/null
  grep -F 'tcpcc: TCP send-buffer ceiling ' "$boot_log" |
    grep -F -- "-> $expected_bytes bytes ($expected_policy," >/dev/null
  assert_tcp_mem_budget_raised "$boot_log"
  grep -F 'tcpcc: M5.1 hosted L3 netdevice passed (' "$boot_log" >/dev/null
  grep -F 'tcpcc-host: panic boundary -> exit(86)' "$boot_log" >/dev/null
}

# Small hosted arenas remain opt-in, but they must at least boot through the
# complete M6 diagnostic boundary.  Zero selects the RAM-sized auto policy.
run_memory_profile memory32-auto 32 0 524288 auto
run_memory_profile memory64-auto 64 0 1048576 auto
# Also prove that an explicit qualification override replaces the auto ceiling
# and remains bounded by the coordinated global tcp_mem policy.
run_memory_profile memory128-explicit 128 3072 3145728 explicit

LINUX_SRC="$SRC" bash "$ROOT/scripts/verify-protected.sh"
printf 'M6.1 hosted native BBR/default-fq configuration and 32/64/128 MiB memory-profile validation succeeded\n'

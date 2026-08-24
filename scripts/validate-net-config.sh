#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${LINUX_SRC:-$ROOT/.deps/linux}"
OUT="$ROOT/.build/kconfig-x86"
FRAGMENT="$ROOT/config/6.18/net-core.config"

LINUX_SRC="$SRC" bash "$ROOT/scripts/prepare-linux.sh"
rm -rf "$OUT"
mkdir -p "$OUT"

# M1 validates that the required symbols and dependencies resolve in upstream
# Linux. This x86 config is only a bootstrap check, not the userspace
# architecture's production configuration.
make -s -C "$SRC" O="$OUT" ARCH=x86 x86_64_defconfig
"$SRC/scripts/kconfig/merge_config.sh" -m -O "$OUT" \
  "$OUT/.config" "$FRAGMENT"
make -s -C "$SRC" O="$OUT" ARCH=x86 olddefconfig

required=(
  CONFIG_HIGH_RES_TIMERS=y
  CONFIG_NET=y
  CONFIG_INET=y
  CONFIG_TCP_CONG_ADVANCED=y
  CONFIG_TCP_CONG_CUBIC=y
  CONFIG_TCP_CONG_BBR=y
  CONFIG_NET_SCHED=y
  CONFIG_NET_SCH_FQ=y
  CONFIG_NET_SCH_DEFAULT=y
  CONFIG_DEFAULT_FQ=y
  'CONFIG_DEFAULT_NET_SCH="fq"'
)

for opt in "${required[@]}"; do
  if ! grep -Fqx "$opt" "$OUT/.config"; then
    echo "required config did not resolve: $opt" >&2
    exit 1
  fi
done

printf 'Networking Kconfig fragment resolved successfully against Linux %s.\n' \
  "$(make -s -C "$SRC" kernelversion)"

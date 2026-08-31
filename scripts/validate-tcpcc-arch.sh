#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${LINUX_SRC:-$ROOT/.deps/linux}"
OUT="${TCPCC_OUT:-$ROOT/.build/tcpcc-out}"

LINUX_SRC="$SRC" bash "$ROOT/scripts/prepare-linux.sh"
rm -rf "$OUT"
mkdir -p "$OUT"

make -s -C "$SRC" O="$OUT" ARCH=tcpcc defconfig

# Always print the architecture gating symbols before assertions so a failed
# CI run explains which Kconfig dependency disabled the port.
grep -E '^(CONFIG_(TCPCC|64BIT|MMU|SMP|COREDUMP|COMPAT|NR_CPUS|PREEMPT|FLATMEM|GENERIC_ATOMIC64|THREAD_INFO_IN_TASK))' \
  "$OUT/.config" | sort || true

required=(
  CONFIG_TCPCC=y
  CONFIG_64BIT=y
  CONFIG_BASE_SMALL=y
  CONFIG_PAGE_SIZE_4KB=y
  CONFIG_NR_CPUS=1
  CONFIG_THREAD_INFO_IN_TASK=y
  CONFIG_TINY_RCU=y
)
for opt in "${required[@]}"; do
  if ! grep -qx "$opt" "$OUT/.config"; then
    echo "tcpcc config requirement missing: $opt" >&2
    exit 1
  fi
done

if grep -qx 'CONFIG_SMP=y' "$OUT/.config"; then
  echo "M2.1 requires a single-vCPU configuration" >&2
  exit 1
fi
if grep -qx 'CONFIG_MMU=y' "$OUT/.config"; then
  echo "M2.1 requires the initial no-MMU bring-up configuration" >&2
  exit 1
fi
if grep -qx 'CONFIG_GENERIC_ATOMIC64=y' "$OUT/.config"; then
  echo "64-bit tcpcc must provide atomic64 primitives instead of GENERIC_ATOMIC64" >&2
  exit 1
fi

make -s -C "$SRC" O="$OUT" ARCH=tcpcc -j"$(nproc)" prepare

LINUX_SRC="$SRC" bash "$ROOT/scripts/verify-protected.sh"

{
  echo "ARCH=tcpcc"
  echo "KERNEL_VERSION=$(make -s -C "$SRC" kernelversion)"
  echo "CONFIG_SHA256=$(sha256sum "$OUT/.config" | awk '{print $1}')"
} > "$ROOT/.build/tcpcc-arch.env"

printf 'ARCH=tcpcc defconfig + prepare succeeded\n'

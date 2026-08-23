#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${LINUX_SRC:-$ROOT/.deps/linux}"
OUT="${TCPCC_LINK_OUT:-$ROOT/.build/tcpcc-link-out}"

LINUX_SRC="$SRC" bash "$ROOT/scripts/prepare-linux.sh"
rm -rf "$OUT"
mkdir -p "$OUT"

make -s -C "$SRC" O="$OUT" ARCH=tcpcc defconfig

# M2.2 intentionally asks Kbuild for a complete linked kernel rather than
# hiding unresolved architecture symbols in a partial relocatable object.
make -s -C "$SRC" O="$OUT" ARCH=tcpcc -j"$(nproc)" vmlinux

test -s "$OUT/vmlinux"
readelf -h "$OUT/vmlinux" > "$ROOT/.build/tcpcc-vmlinux.elf-header"

LINUX_SRC="$SRC" bash "$ROOT/scripts/verify-protected.sh"

{
  echo "ARCH=tcpcc"
  echo "KERNEL_VERSION=$(make -s -C "$SRC" kernelversion)"
  echo "VMLINUX_SHA256=$(sha256sum "$OUT/vmlinux" | awk '{print $1}')"
  echo "VMLINUX_SIZE=$(stat -c '%s' "$OUT/vmlinux")"
} > "$ROOT/.build/tcpcc-link.env"

printf 'ARCH=tcpcc vmlinux linked successfully\n'

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${LINUX_SRC:-$ROOT/.deps/linux}"
OUT="${TCPCC_LINK_OUT:-$ROOT/.build/tcpcc-link-out}"
LINK_LOG="$ROOT/.build/tcpcc-vmlinux.link.log"

LINUX_SRC="$SRC" bash "$ROOT/scripts/prepare-linux.sh"
rm -rf "$OUT"
mkdir -p "$OUT" "$ROOT/.build"
rm -f "$LINK_LOG"

make -s -C "$SRC" O="$OUT" ARCH=tcpcc defconfig

# M2.2 intentionally asks Kbuild for a complete linked kernel rather than
# hiding unresolved architecture symbols in a partial relocatable object.
# Keep the full verbose final-link transcript as a durable CI artifact.  The
# pipeline must return make's status, not tee's, so a failed vmlinux link stays
# a failed validation.
set +e
make -C "$SRC" O="$OUT" ARCH=tcpcc V=1 -j"$(nproc)" vmlinux 2>&1 | tee "$LINK_LOG"
make_status=${PIPESTATUS[0]}
set -e
if (( make_status != 0 )); then
  printf 'ARCH=tcpcc vmlinux link failed (make exit %d); see %s\n' \
    "$make_status" "$LINK_LOG" >&2
  exit "$make_status"
fi

test -s "$OUT/vmlinux"
readelf -h "$OUT/vmlinux" > "$ROOT/.build/tcpcc-vmlinux.elf-header"
size -A "$OUT/vmlinux" > "$ROOT/.build/tcpcc-vmlinux.sections"
cp "$OUT/.config" "$ROOT/.build/tcpcc-vmlinux.config"

LINUX_SRC="$SRC" bash "$ROOT/scripts/verify-protected.sh"

{
	section_size() {
		awk -v section="$1" '$1 == section { print $2; found = 1 } END { if (!found) print 0 }' \
			"$ROOT/.build/tcpcc-vmlinux.sections"
	}

  echo "ARCH=tcpcc"
  echo "KERNEL_VERSION=$(make -s -C "$SRC" kernelversion)"
  echo "VMLINUX_SHA256=$(sha256sum "$OUT/vmlinux" | awk '{print $1}')"
  echo "VMLINUX_SIZE=$(stat -c '%s' "$OUT/vmlinux")"
  echo "VMLINUX_TEXT_SIZE=$(section_size .text)"
  echo "VMLINUX_RODATA_SIZE=$(section_size .rodata)"
  echo "VMLINUX_DATA_SIZE=$(section_size .data)"
  echo "VMLINUX_BSS_SIZE=$(section_size .bss)"
  echo "VMLINUX_EH_FRAME_SIZE=$(section_size .eh_frame)"
  echo "CONFIG_ENABLED_COUNT=$(grep -Ec '^CONFIG_[A-Z0-9_]+=(y|m)$' "$OUT/.config")"
} > "$ROOT/.build/tcpcc-link.env"

printf 'ARCH=tcpcc vmlinux linked successfully\n'

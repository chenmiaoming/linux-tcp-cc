#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="$ROOT/linux-overlay/arch/tcpcc"
COMPAT="$ARCH/kernel/compat.c"

symbols=(
  addrconf_add_dev_addr
  devinet_ioctl
  fib_new_table
  fib_table_insert
  ip6_route_add
)

failed=0
for symbol in "${symbols[@]}"; do
  while IFS= read -r match; do
    file="${match%%:*}"
    if [[ "$file" != "$COMPAT" ]]; then
      echo "unstable API $symbol escaped compatibility boundary: $match" >&2
      failed=1
    fi
  done < <(grep -Rns --include='*.c' --include='*.h' \
    -w "$symbol" "$ARCH" || true)
done

if ! grep -Fqx 'obj-y += net.o compat.o l3net.o bridge.o service.o control.o' \
  "$ARCH/kernel/Makefile"; then
  echo "tcpcc compatibility implementation is absent from Kbuild" >&2
  failed=1
fi

if (( failed )); then
  exit 1
fi
echo "TCPCC unstable networking APIs are contained in kernel/compat.c"

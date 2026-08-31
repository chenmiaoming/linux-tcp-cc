#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE="${TCPCC_CANARY_REMOTE:-https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git}"
REF="${TCPCC_CANARY_REF:-master}"
SRC="$ROOT/.deps/linux-next-canary"
OUT="$ROOT/.build/next-kernel-out"
LOG="$ROOT/.build/next-kernel-vmlinux.log"
REPORT="$ROOT/.build/next-kernel.env"
SERIES="$ROOT/patches/series"
OVERLAY="$ROOT/linux-overlay"

case "$SRC:$OUT" in
  "$ROOT"/*:"$ROOT"/*) ;;
  *) echo "refusing unsafe canary paths" >&2; exit 1 ;;
esac

rm -rf "$SRC" "$OUT"
mkdir -p "$SRC" "$OUT" "$ROOT/.build"
git -C "$SRC" init -q
git -C "$SRC" remote add origin "$REMOTE"
git -C "$SRC" fetch --force --depth=1 origin "$REF"
git -C "$SRC" checkout --detach -f FETCH_HEAD

commit="$(git -C "$SRC" rev-parse HEAD)"
version="$(make -s -C "$SRC" kernelversion)"
cat > "$REPORT" <<EOF
LINUX_REMOTE=$REMOTE
LINUX_REF=$REF
LINUX_VERSION=$version
LINUX_COMMIT=$commit
EOF

while IFS= read -r raw || [[ -n "$raw" ]]; do
  entry="${raw%%#*}"
  entry="${entry#"${entry%%[![:space:]]*}"}"
  entry="${entry%"${entry##*[![:space:]]}"}"
  [[ -z "$entry" ]] && continue
  git -C "$SRC" apply --check "$ROOT/patches/$entry"
  git -C "$SRC" apply "$ROOT/patches/$entry"
done < "$SERIES"

while IFS= read -r -d '' source; do
  rel="${source#"$OVERLAY/"}"
  target="$SRC/$rel"
  if [[ -e "$target" || -L "$target" ]]; then
    echo "next-kernel overlay collision: $rel" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$target")"
  cp -p "$source" "$target"
done < <(find "$OVERLAY" -type f -print0 | sort -z)

bash "$ROOT/scripts/check-portability-boundary.sh"
git -C "$SRC" diff --check
make -s -C "$SRC" O="$OUT" ARCH=tcpcc defconfig

set +e
make -C "$SRC" O="$OUT" ARCH=tcpcc V=1 -j"$(nproc)" vmlinux \
  2>&1 | tee "$LOG"
make_status=${PIPESTATUS[0]}
set -e

if (( make_status != 0 )); then
  echo "next-kernel ARCH=tcpcc link failed for $version ($commit)" >&2
  exit "$make_status"
fi
test -s "$OUT/vmlinux"
printf 'VMLINUX_SHA256=%s\n' "$(sha256sum "$OUT/vmlinux" | awk '{print $1}')" \
  >> "$REPORT"
printf 'VMLINUX_SIZE=%s\n' "$(stat -c '%s' "$OUT/vmlinux")" >> "$REPORT"
printf 'ARCH=tcpcc linked against next kernel %s (%s)\n' "$version" "$commit"

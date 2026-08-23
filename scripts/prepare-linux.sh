#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${LINUX_SRC:-$ROOT/.deps/linux}"
SERIES="$ROOT/patches/series"
OUT="$ROOT/.build"

LINUX_SRC="$SRC" bash "$ROOT/scripts/fetch-linux.sh"
LINUX_SRC="$SRC" bash "$ROOT/scripts/verify-protected.sh"

: > "$OUT/patches.sha256"
patch_count=0
while IFS= read -r raw || [[ -n "$raw" ]]; do
  entry="${raw%%#*}"
  entry="${entry#"${entry%%[![:space:]]*}"}"
  entry="${entry%"${entry##*[![:space:]]}"}"
  [[ -z "$entry" ]] && continue

  patch="$ROOT/patches/$entry"
  if [[ ! -f "$patch" ]]; then
    echo "patch listed in series does not exist: $entry" >&2
    exit 1
  fi

  git -C "$SRC" apply --check "$patch"
  git -C "$SRC" apply "$patch"
  sha256sum "$patch" >> "$OUT/patches.sha256"
  patch_count=$((patch_count + 1))
done < "$SERIES"

git -C "$SRC" diff --check
LINUX_SRC="$SRC" bash "$ROOT/scripts/verify-protected.sh"

{
  cat "$OUT/upstream.env"
  printf 'PATCH_COUNT=%d\n' "$patch_count"
  printf 'SERIES_SHA256=%s\n' "$(sha256sum "$SERIES" | awk '{print $1}')"
} > "$OUT/prepared.env"

printf 'Prepared Linux tree with %d project patch(es): %s\n' "$patch_count" "$SRC"

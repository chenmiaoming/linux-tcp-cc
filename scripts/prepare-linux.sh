#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${LINUX_SRC:-$ROOT/.deps/linux}"
SERIES="$ROOT/patches/series"
OVERLAY="$ROOT/linux-overlay"
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

: > "$OUT/overlay.sha256"
overlay_count=0
if [[ -d "$OVERLAY" ]]; then
  while IFS= read -r -d '' source; do
    rel="${source#"$OVERLAY/"}"
    target="$SRC/$rel"

    # linux-overlay is intentionally append-only relative to pristine upstream.
    # Any change to an existing upstream file must be an explicit patch instead.
    if [[ -e "$target" || -L "$target" ]]; then
      echo "overlay collision with upstream path: $rel" >&2
      exit 1
    fi

    mkdir -p "$(dirname "$target")"
    cp -p "$source" "$target"
    printf '%s  %s\n' "$(sha256sum "$source" | awk '{print $1}')" "$rel" >> "$OUT/overlay.sha256"
    overlay_count=$((overlay_count + 1))
  done < <(find "$OVERLAY" -type f -print0 | sort -z)
fi

git -C "$SRC" diff --check
LINUX_SRC="$SRC" bash "$ROOT/scripts/verify-protected.sh"

{
  cat "$OUT/upstream.env"
  printf 'PATCH_COUNT=%d\n' "$patch_count"
  printf 'OVERLAY_FILE_COUNT=%d\n' "$overlay_count"
  printf 'SERIES_SHA256=%s\n' "$(sha256sum "$SERIES" | awk '{print $1}')"
  printf 'OVERLAY_SHA256=%s\n' "$(sha256sum "$OUT/overlay.sha256" | awk '{print $1}')"
} > "$OUT/prepared.env"

printf 'Prepared Linux tree with %d project patch(es) and %d overlay file(s): %s\n' \
  "$patch_count" "$overlay_count" "$SRC"

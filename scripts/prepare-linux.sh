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

# M4 and later build native Linux networking code.  Keep this as a preparation
# invariant so an incomplete upstream checkout is diagnosed before Kbuild turns
# it into a misleading architecture-local include failure.
if [[ ! -f "$SRC/include/linux/in.h" ]]; then
  echo "prepared Linux tree is missing required header: include/linux/in.h" >&2
  echo "prepared HEAD: $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)" >&2
  echo "HEAD tree entry:" >&2
  git -C "$SRC" ls-tree HEAD -- include/linux/in.h >&2 || true
  echo "working-tree status:" >&2
  git -C "$SRC" status --short --untracked-files=all >&2 || true
  echo "nearby networking headers:" >&2
  find "$SRC/include/linux" -maxdepth 1 -type f -name 'in*.h' -print 2>/dev/null | sort >&2 || true
  exit 1
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

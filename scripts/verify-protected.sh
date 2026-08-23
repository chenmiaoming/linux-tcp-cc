#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${LINUX_SRC:-$ROOT/.deps/linux}"
HASHES="$ROOT/upstream/protected.sha256"
ALLOWLIST="$ROOT/upstream/protected-allowlist.txt"

if [[ ! -d "$SRC" ]]; then
  echo "Linux source tree not found: $SRC" >&2
  exit 1
fi

is_allowlisted() {
  local path="$1"
  grep -Ev '^[[:space:]]*(#|$)' "$ALLOWLIST" | grep -Fxq "$path"
}

failed=0
while read -r expected path; do
  [[ -z "${expected:-}" || "$expected" == \#* ]] && continue

  if [[ ! -f "$SRC/$path" ]]; then
    echo "protected source missing: $path" >&2
    failed=1
    continue
  fi

  actual="$(sha256sum "$SRC/$path" | awk '{print $1}')"
  if [[ "$actual" == "$expected" ]]; then
    printf 'protected source OK: %s\n' "$path"
    continue
  fi

  if is_allowlisted "$path"; then
    printf 'protected source differs but is allowlisted: %s\n' "$path" >&2
  else
    printf 'protected source modified: %s\n  expected %s\n  actual   %s\n' \
      "$path" "$expected" "$actual" >&2
    failed=1
  fi
done < "$HASHES"

exit "$failed"

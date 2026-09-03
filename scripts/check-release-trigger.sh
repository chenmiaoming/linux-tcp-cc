#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

BASE_COMMIT="${1:-HEAD^}"
HEAD_COMMIT="${2:-HEAD}"

git rev-parse --verify "$BASE_COMMIT^{commit}" >/dev/null
git rev-parse --verify "$HEAD_COMMIT^{commit}" >/dev/null

eligible=false
set +e
git diff --quiet "$BASE_COMMIT" "$HEAD_COMMIT" -- upstream/linux.env
diff_status=$?
set -e
case "$diff_status" in
  0) ;;
  1) eligible=true ;;
  *) exit "$diff_status" ;;
esac

printf 'release_eligible=%s\n' "$eligible"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'eligible=%s\n' "$eligible" >> "$GITHUB_OUTPUT"
fi

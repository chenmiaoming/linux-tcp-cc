#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1091
source "$ROOT/upstream/linux.env"

series_version="${LINUX_SERIES%.y}"
mapfile -t tags < <(
  git ls-remote --tags --refs "$LINUX_REMOTE" "refs/tags/v${series_version}.*" |
    awk '{ sub("refs/tags/", "", $2); print $2 }' |
    grep -E "^v${series_version//./\\.}\\.[0-9]+$" |
    sort -V
)

if (( ${#tags[@]} == 0 )); then
  echo "no stable tags found for Linux $LINUX_SERIES" >&2
  exit 1
fi

current_index=-1
for index in "${!tags[@]}"; do
  if [[ "${tags[$index]}" == "$LINUX_TAG" ]]; then
    current_index=$index
    break
  fi
done

if (( current_index < 0 )); then
  echo "pinned tag $LINUX_TAG is absent from $LINUX_REMOTE" >&2
  exit 1
fi

latest_tag="${tags[${#tags[@]} - 1]}"
next_tag=""
if (( current_index + 1 < ${#tags[@]} )); then
  next_tag="${tags[$((current_index + 1))]}"
fi

update_available=false
if [[ -n "$next_tag" ]]; then
  update_available=true
fi

printf 'Linux %s pin: current=%s latest=%s' \
  "$LINUX_SERIES" "$LINUX_TAG" "$latest_tag"
if [[ -n "$next_tag" ]]; then
  printf ' next=%s\n' "$next_tag"
else
  printf ' (current)\n'
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'series=%s\n' "$LINUX_SERIES"
    printf 'current_tag=%s\n' "$LINUX_TAG"
    printf 'latest_tag=%s\n' "$latest_tag"
    printf 'next_tag=%s\n' "$next_tag"
    printf 'update_available=%s\n' "$update_available"
  } >> "$GITHUB_OUTPUT"
fi

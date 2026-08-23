#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/upstream/linux.env"
SRC="${LINUX_SRC:-$ROOT/.deps/linux}"
OUT="$ROOT/.build"

# shellcheck disable=SC1090
source "$LOCK"

mkdir -p "$(dirname "$SRC")" "$OUT"

if [[ ! -d "$SRC/.git" ]]; then
  mkdir -p "$SRC"
  git -C "$SRC" init -q
  git -C "$SRC" remote add origin "$LINUX_REMOTE"
else
  git -C "$SRC" remote set-url origin "$LINUX_REMOTE"
fi

git -C "$SRC" fetch --force --depth=1 origin \
  "refs/tags/$LINUX_TAG:refs/tags/$LINUX_TAG"

git -C "$SRC" checkout --detach -f "$LINUX_TAG"
git -C "$SRC" clean -ffdqx

actual_version="$(make -s -C "$SRC" kernelversion)"
if [[ "$actual_version" != "$LINUX_VERSION" ]]; then
  echo "kernel version mismatch: expected $LINUX_VERSION, got $actual_version" >&2
  exit 1
fi

resolved_commit="$(git -C "$SRC" rev-parse HEAD)"
if [[ "$resolved_commit" != "$LINUX_COMMIT" ]]; then
  echo "upstream commit mismatch: expected $LINUX_COMMIT, got $resolved_commit" >&2
  exit 1
fi

tag_type="$(git -C "$SRC" cat-file -t "$LINUX_TAG")"
if [[ "$tag_type" != "tag" ]]; then
  echo "$LINUX_TAG is not an annotated upstream tag" >&2
  exit 1
fi

protected=(
  net/ipv4/tcp_bbr.c
  net/ipv4/tcp_rate.c
  net/ipv4/tcp_recovery.c
  net/sched/sch_fq.c
)

for path in "${protected[@]}"; do
  if [[ ! -f "$SRC/$path" ]]; then
    echo "required upstream source missing: $path" >&2
    exit 1
  fi
done

sha256sum "${protected[@]/#/$SRC/}" > "$OUT/protected-upstream.sha256"

cat > "$OUT/upstream.env" <<EOF
LINUX_REMOTE=$LINUX_REMOTE
LINUX_SERIES=$LINUX_SERIES
LINUX_TAG=$LINUX_TAG
LINUX_VERSION=$LINUX_VERSION
LINUX_COMMIT=$resolved_commit
EOF

printf 'Linux upstream: %s (%s)\n' "$LINUX_TAG" "$resolved_commit"
printf 'Source tree: %s\n' "$SRC"

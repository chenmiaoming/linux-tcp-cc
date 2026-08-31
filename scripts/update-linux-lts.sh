#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_TAG="${1:-}"

# shellcheck disable=SC1091
source "$ROOT/upstream/linux.env"

series_version="${LINUX_SERIES%.y}"
if [[ ! "$TARGET_TAG" =~ ^v${series_version//./\\.}\.[0-9]+$ ]]; then
  echo "usage: $0 v${series_version}.PATCH" >&2
  exit 2
fi
if [[ "$TARGET_TAG" == "$LINUX_TAG" ]]; then
  echo "$TARGET_TAG is already pinned" >&2
  exit 2
fi
oldest="$(printf '%s\n%s\n' "$LINUX_TAG" "$TARGET_TAG" | sort -V | head -n 1)"
if [[ "$oldest" != "$LINUX_TAG" ]]; then
  echo "refusing to move $LINUX_SERIES backwards: $LINUX_TAG -> $TARGET_TAG" >&2
  exit 2
fi

temporary_source="$(mktemp -d "${TMPDIR:-/tmp}/tcpcc-linux-update.XXXXXX")"
trap 'rm -rf -- "$temporary_source"' EXIT

git -C "$temporary_source" init -q
git -C "$temporary_source" remote add origin "$LINUX_REMOTE"
git -C "$temporary_source" fetch --force --depth=1 origin \
  "refs/tags/$TARGET_TAG:refs/tags/$TARGET_TAG"

if [[ "$(git -C "$temporary_source" cat-file -t "$TARGET_TAG")" != tag ]]; then
  echo "$TARGET_TAG is not an annotated upstream tag" >&2
  exit 1
fi

target_commit="$(git -C "$temporary_source" rev-parse "$TARGET_TAG^{commit}")"
git -C "$temporary_source" checkout --detach -q "$target_commit"
target_version="$(make -s -C "$temporary_source" kernelversion)"
if [[ "v$target_version" != "$TARGET_TAG" ]]; then
  echo "tag/version mismatch: $TARGET_TAG contains Linux $target_version" >&2
  exit 1
fi

protected=(
  net/ipv4/tcp_bbr.c
  net/ipv4/tcp_rate.c
  net/ipv4/tcp_recovery.c
  net/sched/sch_fq.c
)
for path in "${protected[@]}"; do
  if [[ ! -f "$temporary_source/$path" ]]; then
    echo "required protected source missing from $TARGET_TAG: $path" >&2
    exit 1
  fi
done

cat > "$ROOT/upstream/linux.env" <<EOF
# SPDX-License-Identifier: GPL-2.0-only
# Source of truth for the $LINUX_SERIES product branch.
LINUX_REMOTE=$LINUX_REMOTE
LINUX_SERIES=$LINUX_SERIES
LINUX_TAG=$TARGET_TAG
LINUX_VERSION=$target_version
LINUX_COMMIT=$target_commit
EOF

{
  printf '# Linux %s / %s\n' "$TARGET_TAG" "$target_commit"
  for path in "${protected[@]}"; do
    sha256sum "$temporary_source/$path" |
      sed "s#  $temporary_source/#  #"
  done
} > "$ROOT/upstream/protected.sha256"

python3 - "$ROOT/README.md" "$TARGET_TAG" <<'PY'
from pathlib import Path
import re
import sys

readme = Path(sys.argv[1])
target = sys.argv[2]
text = readme.read_text(encoding="utf-8")
updated, count = re.subn(
    r"Current pinned upstream baseline: Linux `v6\.18\.[0-9]+`",
    f"Current pinned upstream baseline: Linux `{target}`",
    text,
    count=1,
)
if count != 1:
    raise SystemExit("README pinned baseline was not updated exactly once")
readme.write_text(updated, encoding="utf-8")
PY

printf 'Updated %s from %s to %s (%s)\n' \
  "$LINUX_SERIES" "$LINUX_TAG" "$TARGET_TAG" "$target_commit"

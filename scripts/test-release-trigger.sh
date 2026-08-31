#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_REPO="$(mktemp -d "${TMPDIR:-/tmp}/tcpcc-release-trigger.XXXXXX")"
trap 'rm -rf -- "$TEST_REPO"' EXIT

git -C "$TEST_REPO" init -q
git -C "$TEST_REPO" config user.name tcpcc-test
git -C "$TEST_REPO" config user.email tcpcc-test.invalid
mkdir -p "$TEST_REPO/upstream"
printf 'LINUX_TAG=v6.18.48\n' > "$TEST_REPO/upstream/linux.env"
printf 'initial\n' > "$TEST_REPO/README.md"
git -C "$TEST_REPO" add upstream/linux.env README.md
git -C "$TEST_REPO" commit -qm initial

printf 'ordinary project change\n' >> "$TEST_REPO/README.md"
git -C "$TEST_REPO" add README.md
git -C "$TEST_REPO" commit -qm ordinary
ordinary="$({ cd "$TEST_REPO"; GITHUB_OUTPUT= bash "$ROOT/scripts/check-release-trigger.sh"; })"
[[ "$ordinary" == 'release_eligible=false' ]]

printf 'LINUX_TAG=v6.18.49\n' > "$TEST_REPO/upstream/linux.env"
git -C "$TEST_REPO" add upstream/linux.env
git -C "$TEST_REPO" commit -qm lts-update
lts="$({ cd "$TEST_REPO"; GITHUB_OUTPUT= bash "$ROOT/scripts/check-release-trigger.sh"; })"
[[ "$lts" == 'release_eligible=true' ]]

printf 'Release trigger contract passed (ordinary=false, LTS pin=true)\n'

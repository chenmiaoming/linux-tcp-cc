#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VMLINUX="${VMLINUX:-$ROOT/.build/tcpcc-bootstrap-out/vmlinux}"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT/.build/release}"
NATIVE_CLI="${NATIVE_CLI:-$ROOT/.build/native/tcpcc}"
TARGET="linux-x86_64-glibc"

# shellcheck disable=SC1091
source "$ROOT/upstream/linux.env"

if [[ ! -x "$VMLINUX" ]]; then
  echo "release vmlinux is not executable: $VMLINUX" >&2
  exit 1
fi
if [[ ! -x "$NATIVE_CLI" ]]; then
  echo "release CLI is not executable; run make native-build first" >&2
  exit 1
fi
if [[ "$LINUX_TAG" != "v$LINUX_VERSION" ]]; then
  echo "release pin mismatch: $LINUX_TAG != v$LINUX_VERSION" >&2
  exit 1
fi

for executable in "$VMLINUX" "$NATIVE_CLI"; do
  if ! readelf -hW "$executable" | grep -Eq \
      'Machine:[[:space:]]+Advanced Micro Devices X86-64'; then
    echo "release executable is not x86-64: $executable" >&2
    exit 1
  fi
done
if readelf -lW "$VMLINUX" | grep -q 'INTERP'; then
  echo "release vmlinux unexpectedly has a program interpreter" >&2
  exit 1
fi

release_commit="$(git -C "$ROOT" rev-parse HEAD)"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" show -s --format=%ct HEAD)}"
package_name="tcpcc-${LINUX_VERSION}-${TARGET}"
archive="$OUTPUT_DIR/$package_name.tar.xz"
checksum="$archive.sha256"
manifest="$OUTPUT_DIR/$package_name.manifest.env"
stage_root="$ROOT/.build/release-stage"
package_root="$stage_root/$package_name"

rm -rf -- "$stage_root"
mkdir -p "$package_root/bin" "$package_root/libexec/tcpcc" \
  "$package_root/share/doc/tcpcc" "$OUTPUT_DIR"
install -m 0755 "$NATIVE_CLI" "$package_root/bin/tcpcc"
install -m 0755 "$VMLINUX" "$package_root/libexec/tcpcc/vmlinux"
install -m 0644 "$ROOT/LICENSE" "$package_root/share/doc/tcpcc/LICENSE"

cli_sha256="$(sha256sum "$package_root/bin/tcpcc" | awk '{print $1}')"
vmlinux_sha256="$(sha256sum "$package_root/libexec/tcpcc/vmlinux" | awk '{print $1}')"

cat > "$package_root/share/doc/tcpcc/RELEASE.env" <<EOF
TCPCC_RELEASE_SCHEMA=1
TCPCC_VERSION=$LINUX_VERSION
TCPCC_RELEASE_TAG=$LINUX_TAG
TCPCC_RELEASE_COMMIT=$release_commit
TCPCC_TARGET=$TARGET
LINUX_SERIES=$LINUX_SERIES
LINUX_TAG=$LINUX_TAG
LINUX_VERSION=$LINUX_VERSION
LINUX_COMMIT=$LINUX_COMMIT
TCPCC_CLI_SHA256=$cli_sha256
TCPCC_VMLINUX_SHA256=$vmlinux_sha256
EOF

cat > "$package_root/share/doc/tcpcc/README.md" <<EOF
# tcpcc $LINUX_VERSION binary package

This package contains the native C supervisor and its hosted Linux vmlinux for
x86-64 glibc systems. It has no Python runtime dependency.

Install under the default prefix:

    sudo tar -xJf $package_name.tar.xz -C /usr/local --strip-components=1

The command resolves the adjacent hosted image automatically:

    /usr/local/bin/tcpcc --help

Runtime prerequisites include /dev/net/tun, CAP_NET_ADMIN, IP forwarding for
the selected address family, and one supported nftables/iptables backend.
EOF

cat > "$package_root/share/doc/tcpcc/SOURCE.md" <<EOF
# Corresponding source and provenance

- tcpcc release commit: https://github.com/chenmiaoming/linux-tcp-cc/tree/$release_commit
- upstream Linux tag: https://git.kernel.org/stable/h/$LINUX_TAG
- upstream Linux commit: $LINUX_COMMIT

The repository's upstream/linux.env, patches/series, linux-overlay directory,
and scripts/prepare-linux.sh reproduce the exact hosted Linux source used for
this binary. The complete project and upstream sources are available from the
two repositories above under GPL-2.0-only.
EOF

cp "$package_root/share/doc/tcpcc/RELEASE.env" "$manifest"
rm -f -- "$archive" "$checksum"
tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner \
  --mtime="@$source_date_epoch" -C "$stage_root" -cJf "$archive" "$package_name"
(
  cd "$OUTPUT_DIR"
  sha256sum "$(basename "$archive")" > "$(basename "$checksum")"
)

printf 'Release package: %s\n' "$archive"
printf 'Release checksum: %s\n' "$checksum"
printf 'Release manifest: %s\n' "$manifest"

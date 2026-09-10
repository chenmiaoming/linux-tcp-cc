# Linux LTS release and packaging policy

The `6.18.y` branch is a product branch tied to the upstream Linux 6.18
longterm series. `upstream/linux.env` is its only release-version source. A
tcpcc release tag is exactly the pinned annotated upstream tag, for example
`v6.18.50`; tcpcc does not invent an unrelated application version.

## Sequential LTS updates

`.github/workflows/linux-lts-update.yml` checks the kernel.org stable Git
repository once per day. When newer tags exist, it selects only the first tag
after the current pin. It then creates one `automation/linux-v6.18.N` pull
request containing:

- the exact annotated upstream tag and peeled commit;
- the matching value reported by the upstream kernel `Makefile`;
- regenerated hashes for the protected BBR, rate-sampling, recovery, and fq
  sources; and
- the human-facing baseline in `README.md`.

The workflow explicitly dispatches every validation workflow because GitHub
places pull-request runs created through the repository `GITHUB_TOKEN` behind
an additional approval gate. It never merges the pull request. A maintainer
must review the upstream provenance and CI results before merging.

The repository's Actions settings must enable **Allow GitHub Actions to create
and approve pull requests** for `GITHUB_TOKEN` to open the update PR. The
repository-wide default token permission can remain read-only: this scheduled
workflow requests only `actions`, `contents`, and `pull-requests` write access,
and none of its steps approve or merge a change.

If several upstream patches appeared while automation was unavailable, only
the oldest missing patch is proposed. After that release is merged and
published, the next daily run proposes the following patch. This preserves the
one-upstream-patch/one-tcpcc-release history instead of silently jumping from,
for example, 6.18.45 to 6.18.48.

The update can also be prepared manually:

```bash
bash scripts/check-linux-lts.sh
bash scripts/update-linux-lts.sh v6.18.51
```

## Release gate

`.github/workflows/release.yml` listens for a successful complete `TCPCC
hosted bootstrap` run on the repository's `6.18.y` branch. Pull-request runs,
forks, failed runs, and topic branches cannot publish. It additionally requires
the exact validated commit to change `upstream/linux.env` relative to its first
parent. Ordinary feature, performance, documentation, and CI pull requests are
therefore never Release-producing commits. The release job checks out the exact
validated LTS-update commit and downloads the hosted image produced by that
same workflow run.

Before publication it builds and runs the native C boundary tests for both
supported libc targets. The release build baselines are deliberately pinned:
Ubuntu 22.04 for the glibc supervisor and Alpine 3.22 for the musl supervisor.
The musl build runs in an Alpine container with Alpine's native GCC/musl and
Linux UAPI headers. Both native supervisors are packaged with the same
already-validated hosted `vmlinux`. The release job extracts both archives,
executes each supervisor's `--help` in a matching libc environment, and verifies
that each manifest identifies the expected target. A tag or Release that
already exists is never overwritten. Ordinary project commits accumulate on
`6.18.y` and ship only when a later pull request advances the upstream Linux
pin. A security fix that cannot wait requires an explicit versioning-policy
change rather than silently replacing an artifact.

The libc build baselines do not follow floating `latest` tags. Moving either
baseline is an explicit maintenance change so the minimum userspace ABI does
not drift silently as CI runner images evolve.

The normal M9 pull-request CI uses the same Ubuntu 22.04 and Alpine 3.22
baselines. It builds and runs `native-check` for both libc targets so portability
regressions are found before the next LTS release. The Alpine job also uploads
the resulting musl supervisor as a short-lived Actions artifact for real-machine
smoke testing.

## Binary archives

Each release publishes two x86-64 archives:

```text
tcpcc-6.18.N-linux-x86_64-glibc.tar.xz
tcpcc-6.18.N-linux-x86_64-musl.tar.xz
```

Each contains:

```text
bin/tcpcc
libexec/tcpcc/vmlinux
share/doc/tcpcc/LICENSE
share/doc/tcpcc/README.md
share/doc/tcpcc/RELEASE.env
share/doc/tcpcc/SOURCE.md
```

The archive root is relocatable. Extracting it beneath `/usr/local` gives the
same layout as `make install`, and the native command discovers
`../libexec/tcpcc/vmlinux` relative to `/proc/self/exe`.

The `glibc` archive contains a dynamically linked supervisor built on Ubuntu
22.04. The `musl` archive contains a dynamically linked supervisor built in
Alpine 3.22 and uses `/lib/ld-musl-x86_64.so.1`, matching x86-64 Alpine Linux.
The hosted `vmlinux` itself is the same `ET_EXEC` image in both archives and has
no userspace dynamic-loader dependency.

The musl supervisor is intentionally **dynamically linked**, not fully static.
The default `nft-lib` firewall backend loads the target system's
`libnftables.so` at runtime with `dlopen(3)`, so a fully static-musl artifact
would make the default backend contract misleading. Alpine deployments should
install the normal nftables/libnftables runtime when using `nft-lib`, or select
one of tcpcc's explicit executable/iptables compatibility backends when
appropriate.

`RELEASE.env` records the tcpcc commit, upstream Linux tag/commit, target, and
SHA-256 hashes of both executables. The Release also attaches the manifest and
an archive checksum. `SOURCE.md` identifies both exact source repositories and
the repository scripts that reconstruct the prepared hosted Linux tree.

CI or a maintainer with an already validated `vmlinux` can create either
package surface explicitly. Reproducing the release libc baselines means using
Ubuntu 22.04 for glibc and Alpine 3.22 for musl:

```bash
# glibc on Ubuntu 22.04
make native-build
make VMLINUX=/path/to/validated/vmlinux \
  NATIVE_CLI=.build/native/tcpcc \
  TARGET=linux-x86_64-glibc \
  release-package

# musl supervisor in Alpine 3.22
docker run --rm -v "$PWD:/src" -w /src alpine:3.22 sh -euxc '
  apk add --no-cache build-base linux-headers binutils
  rm -rf .build/native
  make native-build
  make native-check
'

make VMLINUX=/path/to/validated/vmlinux \
  NATIVE_CLI=.build/native/tcpcc \
  TARGET=linux-x86_64-musl \
  release-package
```

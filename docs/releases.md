# Linux LTS release and packaging policy

The `6.18.y` branch is a product branch tied to the upstream Linux 6.18
longterm series. `upstream/linux.env` is its only release-version source. A
tcpcc release tag is exactly the pinned annotated upstream tag, for example
`v6.18.45`; tcpcc does not invent an unrelated application version.

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
bash scripts/update-linux-lts.sh v6.18.46
```

## Release gate

`.github/workflows/release.yml` listens for a successful complete `TCPCC
hosted bootstrap` run on the repository's `6.18.y` branch. Pull-request runs,
forks, failed runs, and topic branches cannot publish. The release job checks
out the exact validated commit and downloads the hosted image produced by that
same workflow run.

Before publication it also builds and runs the native C boundary tests in CI,
constructs the archive, extracts it into a clean directory, and proves the
installed relative layout. A tag or Release that already exists is never
overwritten. Ordinary project commits after a version is published therefore
do not respin that upstream version; they ship with the next Linux 6.18.y
patch. A security fix that cannot wait requires an explicit versioning-policy
change rather than silently replacing an artifact.

## Binary archive

The release archive is named:

```text
tcpcc-6.18.N-linux-x86_64-glibc.tar.xz
```

It contains:

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
`../libexec/tcpcc/vmlinux` relative to `/proc/self/exe`. Releases are currently
built on the `ubuntu-22.04` GitHub image and are labelled `glibc` rather than
claiming compatibility with every Linux libc.

`RELEASE.env` records the tcpcc commit, upstream Linux tag/commit, target, and
SHA-256 hashes of both executables. The Release also attaches the manifest and
an archive checksum. `SOURCE.md` identifies both exact source repositories and
the repository scripts that reconstruct the prepared hosted Linux tree.

CI or a maintainer with an already validated `vmlinux` can create the same
package surface with:

```bash
make native-build
make VMLINUX=/path/to/validated/vmlinux release-package
```

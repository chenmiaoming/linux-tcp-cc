# linux-tcp-cc

`linux-tcp-cc` is a production-oriented userspace runtime for upstream Linux TCP congestion-control implementations.

The project does **not** reimplement BBR, CUBIC, delivery-rate sampling, TCP loss recovery, or fq pacing. Instead, it aims to run the relevant upstream Linux TCP/networking code with the smallest maintainable userspace architecture/runtime boundary.

## Versioning model

Each supported Linux LTS series has its own long-lived repository branch. The default branch is the newest supported LTS series.

Current branch: `6.18.y`

Current pinned upstream baseline: Linux `v6.18.48` from the kernel.org stable tree.

Patch-level releases inside this branch will follow Linux 6.18.y stable updates after CI and regression validation.

Release tags match the pinned upstream patch exactly (`v6.18.N`). A scheduled
workflow proposes the next sequential stable tag without skipping intermediate
patches. The update remains a normal pull request; after it is merged and the
complete hosted bootstrap workflow succeeds on `6.18.y`, CI publishes the
native C binary and hosted `vmlinux` as an immutable GitHub Release. See
[`docs/releases.md`](docs/releases.md) for the package and maintenance contract.

## Maintenance boundary

The long-term maintenance target is to keep project-specific changes concentrated in the userspace architecture, host runtime, packet netdevice, build/configuration, and control/API layers.

Direct use of version-sensitive networking internals is centralized in the
TCPCC compatibility layer, and a weekly mainline canary detects API drift
before the next LTS migration. See [`docs/porting.md`](docs/porting.md) for the
dependency map and porting procedure.

The following upstream implementation files are treated as protected source and should remain unmodified:

- `net/ipv4/tcp_bbr.c`
- `net/ipv4/tcp_rate.c`
- Linux TCP recovery core
- `net/sched/sch_fq.c`

Any exception requires an explicit design decision and dedicated review; adapting an LTS release must not silently fork congestion-control semantics.

## Development workflow

Development is milestone-driven. Each independently verifiable task is developed on a topic branch and merged into the corresponding LTS branch through a pull request.

The initial roadmap is tracked in GitHub issues M0 through M8. Early milestones establish upstream provenance, the overlay/build system, and the minimal userspace kernel runtime before enabling BBR performance work.

M8's target product is a TUN-backed inbound server TCP front end, described in
[`docs/m8-server-ingress-design.md`](docs/m8-server-ingress-design.md).
Its weekly four-way native/TCPCC CUBIC/BBR transoceanic experiment is documented in
[`docs/m8-high-bdp-iperf.md`](docs/m8-high-bdp-iperf.md).

M9 migrated the installed runtime from Python to a native C supervisor and a
single-owner, event-driven hosted bridge. The process boundary, capacity model,
and CI gates are described in
[`docs/m9-native-event-runtime.md`](docs/m9-native-event-runtime.md).

M11 coalesces packet wakeups, combines TUN RX/TX into one budgeted event pump,
and validates idle and small-packet CPU under 25% and 50% cgroup CPU quotas.
See [`docs/m11-cpu-efficiency.md`](docs/m11-cpu-efficiency.md).

## Server-ingress command

Build and validate the hosted kernel, then install the native C command and
hosted image under `/usr/local`:

```bash
bash ./scripts/validate-tcpcc-bootstrap.sh
sudo make install
```

`VMLINUX=/path/to/vmlinux` and `PREFIX=/another/prefix` may be supplied to
`make install`. The installed runtime contains `bin/tcpcc` and
`libexec/tcpcc/vmlinux` only and has no Python dependency. From an uninstalled
source checkout, run `make native-build`, then use `sudo ./tcpcc` with either
the default `.build/tcpcc-bootstrap-out/vmlinux` or `--kernel PATH`.

Before startup, the operator must provide TUN, forwarding, and the requested
host congestion-control prerequisite. tcpcc reports all missing prerequisites
but does not change global sysctls:

```bash
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding
sysctl net.ipv4.tcp_congestion_control
sysctl net.ipv4.tcp_available_congestion_control
```

IPv4 listeners require `net.ipv4.ip_forward=1`; IPv6 listeners require
`net.ipv6.conf.all.forwarding=1`. Only the forwarding switch for the selected
public address family is required.

The stable server-facing command is:

```bash
sudo tcpcc \
  --listen 203.0.113.10:443 \
  --backend 127.0.0.1:443 \
  --cc bbr
```

IPv6 literals use brackets, as in
`sudo tcpcc --listen '[2001:db8::10]:443' --backend 127.0.0.1:443 --cc bbr`.
The public endpoint and TUN are IPv4 or IPv6 together; the local application
bridge deliberately remains an ordinary IPv4 loopback connection.

The CLI applies no connection admission limit by default and uses a five-second
graceful-shutdown window. Hosted RAM defaults to 128 MiB but is no longer a
compile-time ceiling. Operators can tune the resources or opt into a policy
limit explicitly:

```bash
sudo tcpcc \
  --listen 203.0.113.10:443 \
  --backend 127.0.0.1:443 \
  --cc bbr \
  --memory-mib 512 \
  --max-connections 16384 \
  --shutdown-grace-period 5
```

`--max-connections 0` (the default) disables the admission-policy limit; a
positive value opts into a proxy-style `maxconn` limit up to the current
1048575 handle-encoding boundary. The dynamic bridge allocates 16-KiB direction
buffers only while data is ready and shares a 256-KiB aggregate payload-buffer
budget. Capacity CI, rather than the default configuration, measures the
practical limit in explicit stages. `--memory-mib` has a 128-MiB safety minimum
but no project-defined upper ceiling; an oversized request fails at the host
`mmap`.

The public connection terminates in the hosted Linux stack using BBR; the
ordinary loopback connection to the application is a separate stream bridge.
`nft-lib` is the default packet-steering implementation. `nft-exec` and the
`iptables-nft`/`iptables-legacy` compatibility paths are selected explicitly
with `--firewall-backend` and `--iptables-variant`; an error never triggers a
silent fallback. Readiness and shutdown are emitted as newline-delimited
`tcpcc.runtime.v1` JSON on stdout. On SIGINT or SIGTERM tcpcc closes the hosted
listener, lets active streams finish for the configured grace period, cancels
only the remainder, stops the hosted kernel, removes its exact DNAT resource,
and finally closes the nonpersistent TUN.

## Fetch the pinned Linux source

```bash
bash ./scripts/fetch-linux.sh
cat .build/upstream.env
cat .build/protected-upstream.sha256
```

The kernel source is fetched into `.deps/linux` and is not vendored into this repository.

## License

GPL-2.0. See `LICENSE`.

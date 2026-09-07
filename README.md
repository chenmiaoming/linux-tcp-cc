# linux-tcp-cc

`linux-tcp-cc` lets a server use upstream Linux TCP congestion control on its
**public TCP connections even when the surrounding host/container kernel cannot
provide or select that algorithm**.

The primary motivating environment is a constrained VPS/container such as
OpenVZ: the tenant may be able to use TUN and netfilter, and may run an ordinary
application such as nginx, but cannot replace the provider kernel, load
`tcp_bbr`, or change the host TCP congestion-control policy. In that situation,
changing nginx cannot make the public connection use BBR because the outer
kernel still owns the TCP socket.

TCPCC solves that ownership problem by terminating the public TCP connection in
a small userspace-hosted upstream Linux network stack. The application remains
an ordinary loopback backend:

```text
remote client
    |
    | public TCP packets
    v
outer host DNAT / conntrack
    |
    | raw IPv4 or IPv6 packets
    v
TUN
    |
    v
hosted upstream Linux TCP listener
    |  TCP_CONGESTION = --cc
    |  upstream CUBIC / BBR / recovery / rate sampling / fq
    v
single-owner byte-stream bridge
    |
    | separate ordinary host-loopback TCP connection
    v
127.0.0.1 backend (nginx, HAProxy, application, ...)
```

The stable operator-facing shape is:

```bash
sudo tcpcc \
  --listen 203.0.113.10:443 \
  --backend 127.0.0.1:443 \
  --cc bbr
```

The public connection and the backend connection are deliberately different
TCP legs. `--cc` belongs to the hosted public listener. The outer host's default
or available congestion-control algorithms do **not** need to contain or select
BBR for hosted BBR to work.

The project does **not** reimplement BBR, CUBIC, delivery-rate sampling, TCP
loss recovery, or fq pacing. It runs the relevant upstream Linux networking
code behind the smallest maintainable userspace architecture/runtime boundary.
It is not an embedded-Linux project, SOCKS/HTTP proxy, or generic userspace
network stack.

For the current ownership model, data path, lifecycle, memory/CPU model, and
non-goals, read [`ARCHITECTURE.md`](ARCHITECTURE.md). The repository knowledge
map is [`docs/index.md`](docs/index.md).

## Versioning model

Each supported Linux LTS series has its own long-lived repository branch. The
default branch is the newest supported LTS series.

Current branch: `6.18.y`

Current pinned upstream baseline: Linux `v6.18.49` from the kernel.org stable
tree.

Patch-level releases inside this branch follow Linux 6.18.y stable updates
after CI and regression validation.

Release tags match the pinned upstream patch exactly (`v6.18.N`). A scheduled
workflow proposes the next sequential stable tag without skipping intermediate
patches. The update remains a normal pull request; after it is merged and the
complete hosted bootstrap workflow succeeds on `6.18.y`, CI publishes the
native C binary and hosted `vmlinux` as an immutable GitHub Release. See
[`docs/releases.md`](docs/releases.md) for the package and maintenance contract.

## Maintenance boundary

The long-term maintenance target is to keep project-specific changes
concentrated in the userspace architecture, host runtime, packet netdevice,
build/configuration, and control/API layers.

Direct use of version-sensitive networking internals is centralized in the
TCPCC compatibility layer, and a weekly mainline canary detects API drift
before the next LTS migration. See [`docs/porting.md`](docs/porting.md) for the
dependency map and porting procedure.

The following upstream implementation files are treated as protected source and
should remain unmodified:

- `net/ipv4/tcp_bbr.c`
- `net/ipv4/tcp_rate.c`
- Linux TCP recovery core
- `net/sched/sch_fq.c`

Any exception requires an explicit design decision and dedicated review;
adapting an LTS release must not silently fork congestion-control semantics.

## Development history and current design

Development is milestone-driven. Each independently verifiable task is
developed on a topic branch and merged into the corresponding LTS branch
through a pull request. The milestone documents are retained as design history
and detailed mechanism, while `ARCHITECTURE.md` describes the current composed
system.

M8 introduced the TUN-backed inbound server TCP front end, transactional host
packet steering, and the public/listener versus loopback/backend split. See
[`docs/m8-server-ingress-design.md`](docs/m8-server-ingress-design.md). Its
four-way native/TCPCC CUBIC/BBR transoceanic experiment is documented in
[`docs/m8-high-bdp-iperf.md`](docs/m8-high-bdp-iperf.md).

M9 migrated the installed runtime from Python to a native C supervisor and a
single-owner, event-driven hosted bridge, then removed the fixed connection
admission model. The process boundary, dynamic-flow model, capacity work, and
CI gates are described in
[`docs/m9-native-event-runtime.md`](docs/m9-native-event-runtime.md).

M10 made hosted memory demand-backed and reclaimable, added full memory
lifecycle/stability evidence, and concluded that true online guest-memory
hotplug is not justified by current capacity evidence. See
[`docs/m10-hosted-memory-lifecycle.md`](docs/m10-hosted-memory-lifecycle.md).

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

Before startup, the operator must provide a usable TUN device, the selected
firewall backend, and forwarding for the public address family. tcpcc reports
missing packet-path prerequisites but does not change global sysctls:

```bash
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.forwarding
```

IPv4 listeners require `net.ipv4.ip_forward=1`; IPv6 listeners require
`net.ipv6.conf.all.forwarding=1`. Only the forwarding switch for the selected
public address family is required. The outer host's default and available TCP
congestion-control algorithms are deliberately **not** prerequisites: `--cc`
is applied to the public listener inside the hosted Linux stack and read back
there before the listener is exposed. An outer host using CUBIC, or one that
does not provide BBR at all, can therefore front a hosted BBR endpoint.

The current TUN+DNAT architecture genuinely depends on forwarding. A provider
that exposes TUN/netfilter but locks the relevant forwarding sysctl off is not a
supported deployment merely because hosted congestion control itself is
independent of the host TCP CC policy.

IPv6 literals use brackets, as in:

```bash
sudo tcpcc \
  --listen '[2001:db8::10]:443' \
  --backend 127.0.0.1:443 \
  --cc bbr
```

The public endpoint and TUN are IPv4 or IPv6 together; the local application
bridge deliberately remains an ordinary IPv4 loopback connection.

The CLI applies no connection admission limit by default and uses a five-second
graceful-shutdown window. Hosted RAM defaults to a 128-MiB guest-capacity arena,
but host physical residency is demand-backed and reclaimable. Operators can
tune capacity or opt into a policy limit explicitly:

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
practical limit in explicit stages.

`--memory-mib` has a 128-MiB safety minimum and no project-defined upper bound,
but it remains the startup guest buddy-allocator capacity for that hosted
process. The anonymous mapping is demand-backed, and pages proven free by the
guest are returned to the host; the project does not currently perform online
guest-memory hotplug. An oversized request or later host memory policy failure
still fails explicitly.

The public connection terminates in the hosted Linux stack using the algorithm
selected by `--cc`; the ordinary loopback connection to the application is a
separate stream bridge. `nft-lib` is the default packet-steering implementation.
`nft-exec` and the `iptables-nft`/`iptables-legacy` compatibility paths are
selected explicitly with `--firewall-backend` and `--iptables-variant`; an
error never triggers a silent fallback.

Readiness and shutdown are emitted as newline-delimited `tcpcc.runtime.v1` JSON
on stdout. The native runtime emits aggregate lifecycle events rather than a
per-flow event stream. On SIGINT or SIGTERM tcpcc closes the hosted listener,
lets active streams finish for the configured grace period, cancels only the
remainder, stops the hosted kernel, removes its exact DNAT resource, and finally
closes the nonpersistent TUN.

## Fetch the pinned Linux source

```bash
bash ./scripts/fetch-linux.sh
cat .build/upstream.env
cat .build/protected-upstream.sha256
```

The kernel source is fetched into `.deps/linux` and is not vendored into this
repository.

## License

GPL-2.0. See `LICENSE`.

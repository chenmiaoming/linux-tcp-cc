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
  --forward 203.0.113.10:443=127.0.0.1:443 \
  --cc bbr
```

One tcpcc process may own multiple fixed public forwards by repeating the
atomic `--forward LISTEN=BACKEND` option:

```bash
sudo tcpcc \
  --forward 203.0.113.10:443=127.0.0.1:8443 \
  --forward 203.0.113.10:8443=127.0.0.1:9443 \
  --cc bbr
```

Each `--forward` is one complete public-listener/backend mapping, so pairing does
not depend on option ordering. Routes in one process currently share one TUN/L3
endpoint and therefore must use one public address family and distinct public
TCP ports. The loopback backend remains IPv4 `127.0.0.1:<port>`. `--forward` is the sole operator-facing mapping syntax; separate
`--listen` and `--backend` options are not supported.

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
non-goals, read [`ARCHITECTURE.md`](ARCHITECTURE.md). Exact supervisor signal,
child-process, hosted boot-finalization, and shutdown ordering is documented in
[`docs/runtime-lifecycle.md`](docs/runtime-lifecycle.md). The repository
knowledge map is [`docs/index.md`](docs/index.md).

## Versioning model

Each supported Linux LTS series has its own long-lived repository branch. The
default branch is the newest supported LTS series.

Current branch: `6.18.y`

Current pinned upstream baseline: Linux `v6.18.52` from the kernel.org stable
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
single-owner, event-driven hosted bridge, removed the fixed connection admission
model, and extended one aggregate hosted service plus the native CLI to own
multiple fixed listener/backend routes. The process boundary, dynamic-flow
model, capacity work, multi-listener service/CLI contract, and CI gates are
described in [`docs/m9-native-event-runtime.md`](docs/m9-native-event-runtime.md)
and [`docs/m9-multi-listener-service.md`](docs/m9-multi-listener-service.md).

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

## TOML service configuration

Long-lived deployments may use an explicit, versioned TOML configuration file
instead of spelling out service options on every invocation. tcpcc never loads
a configuration file implicitly; the operator selects it with `--config FILE`.
A minimal configuration is:

```toml
version = 1
cc = "bbr"
memory_mib = 128

[[forward]]
listen = "203.0.113.10:443"
backend = "127.0.0.1:8443"
```

Validate the host prerequisites without creating the TUN, firewall rules, or
hosted process, then start the service with the same file:

```bash
sudo tcpcc --check --config /etc/tcpcc/tcpcc.toml
sudo tcpcc --config /etc/tcpcc/tcpcc.toml
```

`--check` is the only command-line service option that may be combined with
`--config`. Direct service options such as `--forward`, `--cc`, `--memory-mib`,
`--tcp-wmem-max-kib`, and firewall/TUN tuning are rejected when a config file is
selected rather than defining an override-precedence layer. The version-1
schema also supports the same memory, TCP send-autotuning, firewall, TUN,
listener, connection-limit, and shutdown settings used by direct CLI operation.
See [`docs/configuration.md`](docs/configuration.md) for the complete schema and
[`examples/tcpcc.toml`](examples/tcpcc.toml) for a commented starting point.

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
is applied to every public listener inside the hosted Linux stack and read back
there before the listener is exposed. An outer host using CUBIC, or one that
does not provide BBR at all, can therefore front a hosted BBR endpoint.

The current TUN+DNAT architecture genuinely depends on forwarding. A provider
that exposes TUN/netfilter but locks the relevant forwarding sysctl off is not a
supported deployment merely because hosted congestion control itself is
independent of the host TCP CC policy.

IPv6 literals use brackets, as in:

```bash
sudo tcpcc \
  --forward '[2001:db8::10]:443=127.0.0.1:443' \
  --cc bbr
```

The public endpoint and TUN are IPv4 or IPv6 together; the local application
bridge deliberately remains an ordinary IPv4 loopback connection. When multiple
routes are configured in one process, all public listeners must use that same
family. Their public TCP ports must be distinct because DNAT maps every route to
the same hosted TUN guest address while preserving the port; duplicate ports
would collapse onto one hosted endpoint and could not select distinct backends.

The CLI applies no connection admission limit by default and uses a five-second
graceful-shutdown window. Hosted RAM defaults to a 128-MiB guest-capacity arena,
but host physical residency is demand-backed and reclaimable. Operators can
select smaller 32- or 64-MiB arenas for constrained hosts, increase capacity,
or opt into a policy limit explicitly:

```bash
sudo tcpcc \
  --forward 203.0.113.10:443=127.0.0.1:443 \
  --cc bbr \
  --memory-mib 64 \
  --max-connections 16384 \
  --shutdown-grace-period 5
```

`--max-connections 0` (the default) disables the admission-policy limit; a
positive value opts into a proxy-style `maxconn` limit up to the current
1048575 handle-encoding boundary. With multiple listeners this is one aggregate
service-wide limit, not a per-listener limit. The dynamic bridge allocates
16-KiB direction buffers only while data is ready and shares a 256-KiB aggregate
payload-buffer budget. Capacity CI, rather than the default configuration,
measures the practical limit in explicit stages.

`--memory-mib` defaults to 128 MiB, accepts an opt-in minimum of 32 MiB, and has
no project-defined upper bound. It remains the startup guest buddy-allocator
capacity for that hosted process. The anonymous mapping is demand-backed, and
pages proven free by the guest are returned to the host; the project does not
currently perform online guest-memory hotplug. An oversized request or later
host memory policy failure still fails explicitly.

By default the hosted TCP memory policy is the policy produced by upstream
Linux `tcp_init()` for that arena: tcpcc preserves both the RAM-derived
`tcp_wmem[2]` send-autotuning ceiling and the shared `tcp_mem`
low/pressure/high thresholds. On the current kernel this is roughly a 1-MiB
send ceiling for a 128-MiB arena and the ordinary 4-MiB Linux ceiling by about
512 MiB. These are accounting/autotuning limits, not eager allocations.

Qualification or unusual high-BDP deployments may override only the send
ceiling explicitly, for example:

```bash
sudo tcpcc \
  --forward 203.0.113.10:443=127.0.0.1:443 \
  --cc bbr \
  --memory-mib 128 \
  --tcp-wmem-max-kib 3072
```

An explicit ceiling at or below the upstream value leaves the upstream
aggregate `tcp_mem` budget unchanged. If an explicit ceiling raises
`tcp_wmem[2]`, tcpcc raises `tcp_mem` only as needed to retain approximately the
upstream eight-to-one pressure-to-send-ceiling scale, with the pressure point
capped at 12.5% of hosted RAM. The receive-side `tcp_rmem` policy remains
upstream-derived.

The public connection terminates in the hosted Linux stack using the algorithm
selected by `--cc`; the ordinary loopback connection to the application is a
separate stream bridge. `nft-lib` is the default packet-steering implementation.
`nft-exec` and the `iptables-nft`/`iptables-legacy` compatibility paths are
selected explicitly with `--firewall-backend` and `--iptables-variant`; an
error never triggers a silent fallback. Each configured public route owns a
separate exact firewall resource under the same supervisor lifecycle.

Readiness and shutdown are emitted as newline-delimited `tcpcc.runtime.v1` JSON
on stdout. The native runtime emits aggregate lifecycle events rather than a
per-flow event stream. The `ready` event keeps the legacy first-route fields and,
for route-aware consumers, includes `listener_count` plus the complete `routes`
listen/backend/firewall-resource map. On SIGINT or SIGTERM tcpcc closes every
hosted listener, lets active streams finish for the configured grace period,
cancels only the remainder, stops the hosted kernel, removes all owned exact
DNAT resources in reverse order, and finally closes the nonpersistent TUN.
Signal handling, SIGPIPE behavior, child death, and hosted boot readiness are
specified in [`docs/runtime-lifecycle.md`](docs/runtime-lifecycle.md).

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

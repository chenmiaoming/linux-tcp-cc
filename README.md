# linux-tcp-cc

`linux-tcp-cc` is a production-oriented userspace runtime for upstream Linux TCP congestion-control implementations.

The project does **not** reimplement BBR, CUBIC, delivery-rate sampling, TCP loss recovery, or fq pacing. Instead, it aims to run the relevant upstream Linux TCP/networking code with the smallest maintainable userspace architecture/runtime boundary.

## Versioning model

Each supported Linux LTS series has its own long-lived repository branch. The default branch is the newest supported LTS series.

Current branch: `6.18.y`

Current pinned upstream baseline: Linux `v6.18.45` from the kernel.org stable tree.

Patch-level releases inside this branch will follow Linux 6.18.y stable updates after CI and regression validation.

## Maintenance boundary

The long-term maintenance target is to keep project-specific changes concentrated in the userspace architecture, host runtime, packet netdevice, build/configuration, and control/API layers.

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
Its native CUBIC/BBR versus tcpcc BBR high-BDP iperf gate is documented in
[`docs/m8-high-bdp-iperf.md`](docs/m8-high-bdp-iperf.md).

M9 is migrating the installed runtime from Python to a native C supervisor and
a single-owner, event-driven hosted bridge. The process boundary, capacity
model, and staged CI gates are described in
[`docs/m9-native-event-runtime.md`](docs/m9-native-event-runtime.md). The
existing Python command remains the supported entry point until those parity
gates pass.

## Server-ingress command

Build and validate the hosted kernel, then install the command and its private
Python modules under `/usr/local`:

```bash
bash ./scripts/validate-tcpcc-bootstrap.sh
sudo make install
```

`VMLINUX=/path/to/vmlinux` and `PREFIX=/another/prefix` may be supplied to
`make install`. From an uninstalled source checkout, use `sudo ./tcpcc` and
either the default `.build/tcpcc-bootstrap-out/vmlinux` or `--kernel PATH`.

Before startup, the operator must provide TUN, forwarding, and the requested
host congestion-control prerequisite. tcpcc reports all missing prerequisites
but does not change global sysctls:

```bash
sysctl net.ipv4.ip_forward
sysctl net.ipv4.tcp_congestion_control
sysctl net.ipv4.tcp_available_congestion_control
```

The stable server-facing command is:

```bash
sudo tcpcc \
  --listen 203.0.113.10:443 \
  --backend 127.0.0.1:443 \
  --cc bbr
```

The CLI defaults to 4095 simultaneous connections and a five-second
graceful-shutdown window. Operators can still set a lower admission ceiling:

```bash
sudo tcpcc \
  --listen 203.0.113.10:443 \
  --backend 127.0.0.1:443 \
  --cc bbr \
  --max-connections 2048 \
  --shutdown-grace-period 5
```

The dynamic bridge accepts `--max-connections` from 1 through the current 4095
handle-encoding ceiling, allocates 16-KiB direction buffers only while data is
ready, and shares a 256-KiB aggregate payload-buffer budget. M9 capacity CI
holds 4095 simultaneous connections on one listener with zero admission or
bridge-start failures, so 4095 is also the current measured default. The handle
layout remains a ceiling to remove, not a final proxy-scale capacity target.

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

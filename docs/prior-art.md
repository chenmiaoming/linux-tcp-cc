# Prior art and related projects

linux-tcp-cc is **not** the first project to observe that OpenVZ-style
environments can obtain a different TCP implementation by moving the public
socket out of the provider kernel.

The closest prior art is the LKL + HAProxy family. This document records that
lineage and clarifies the different maintenance boundary chosen by tcpcc.

## LKL + HAProxy lineage

### tcp-nanqinlang/lkl-haproxy

[`tcp-nanqinlang/lkl-haproxy`](https://github.com/tcp-nanqinlang/lkl-haproxy)
is an early OpenVZ-oriented LKL/HAProxy implementation. The repository is now
archived, but it established the practical pattern of placing the externally
visible TCP endpoint in LKL while using host networking/TUN/TAP plumbing around
it.

### mzz2017/lkl-haproxy

[`mzz2017/lkl-haproxy`](https://github.com/mzz2017/lkl-haproxy) packaged the
same general approach for several common distributions and BBRPlus. Its
operator surface is based on LKL hijacking, HAProxy, TAP/network scripts, and
shell-managed setup.

### nivrrex/lkl-bbr

[`nivrrex/lkl-bbr`](https://github.com/nivrrex/lkl-bbr) is a more recent LKL
BBRPlus-oriented continuation for OpenVZ. Its documented runtime uses
`liblkl-hijack.so`, `LD_PRELOAD`, an LKL hijack configuration, TAP/iptables,
and a proxy process; it also carries newer LKL/BBRPlus build work.

### nivrrex/lkl-proxy

[`nivrrex/lkl-proxy`](https://github.com/nivrrex/lkl-proxy) replaces HAProxy
with a small Rust Layer-4 proxy specifically for the LKL syscall-hijack
environment. Its documentation records practical compatibility constraints
around epoll/io_uring/splice under that hijack model.

These projects are the reason linux-tcp-cc should **not** be described as “the
first way to run BBR on OpenVZ from userspace.”

## What linux-tcp-cc changes

The shared observation is:

> The kernel/stack that owns the public TCP socket owns its congestion control.

The product boundary is different.

A simplified comparison is:

| Dimension | LKL hijack/proxy family | linux-tcp-cc |
| --- | --- | --- |
| Public TCP owner | LKL stack used through syscall hijacking | hosted upstream Linux listener |
| Application/proxy integration | proxy runs inside the hijacked environment | backend remains ordinary `127.0.0.1` application |
| Typical injection mechanism | `LD_PRELOAD=liblkl-hijack.so` | none for backend application |
| Operator mapping | proxy + LKL/TAP/firewall configuration | atomic `--forward LISTEN=BACKEND` or TOML |
| Packet boundary | commonly TAP/LKL setup | one nonpersistent L3 TUN |
| CC/recovery maintenance goal | depends on selected LKL/patch stack | preserve pinned upstream Linux TCP semantics |
| Runtime owner | application/proxy + hijack integration | standalone native tcpcc supervisor |
| Validation focus | project-specific/manual depending on implementation | privileged CI + published network/memory/CPU evidence |

The table is not a claim that every LKL deployment has the same properties. It
describes the operator/maintenance boundary of the projects linked above.

## Why not simply keep using LKL hijack?

For some deployments, doing so is completely reasonable.

linux-tcp-cc exists because it wants a different set of properties:

1. The backend program should not need to run under a syscall-interposition
   environment.
2. The hosted network stack should be an explicit service component with its
   own lifecycle rather than an implementation detail injected into HAProxy or
   another application.
3. Public listener ownership, congestion-control selection, host packet
   steering, bridge ownership, and cleanup should have one native supervisor.
4. Upstream Linux TCP behavior should remain the primary semantic reference.
5. Multi-listener, IPv6, memory lifecycle, CPU/wakeup behavior, and cleanup
   should be regression-qualified as product contracts.

This is an engineering tradeoff rather than a claim that the LKL approach is
invalid.

## Other userspace TCP stacks

A different family of projects implements TCP itself in userspace. Those
projects may use TUN and may expose proxy/listener APIs, but they make a
different semantic choice from linux-tcp-cc.

For example,
[`rustp2p/tcp_ip`](https://github.com/rustp2p/tcp_ip) is a userspace TCP/IP
stack with IPv4/IPv6 TCP support and packetdrill-based conformance work. It is
interesting related work, but its TCP state machine is its own implementation
rather than the upstream Linux TCP implementation hosted by tcpcc.

Likewise, the maintainer's
[`tcp-shift`](https://github.com/chenmiaoming/tcp-shift) uses lwIP and focuses
on a smaller footprint plus explicit RFC-oriented transport qualification.

See [`docs/upstream-linux-fidelity.md`](upstream-linux-fidelity.md) for why
linux-tcp-cc intentionally chooses the hosted-Linux side of that tradeoff.

## How to describe linux-tcp-cc accurately

A useful short description is:

> linux-tcp-cc is a standalone TUN/DNAT front end that moves public TCP
> ownership into a hosted upstream Linux stack, allowing an ordinary loopback
> application to use Linux BBR/CUBIC even when the surrounding host kernel
> cannot provide or select that algorithm.

Avoid claims such as:

- “first userspace BBR for OpenVZ”;
- “the only way to use BBR without host-kernel control”; or
- “identical performance to bare-metal Linux.”

The project's stronger and more defensible claim is its **upstream Linux
fidelity and standalone maintenance boundary**.

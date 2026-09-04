# linux-tcp-cc architecture

This document describes the **current product architecture**. Milestone documents
under `docs/` explain how individual pieces were developed and validated; they
are useful design history, but this file is the place to start when deciding
what tcpcc is, which component owns a behavior, and whether a proposed change
fits the product.

## The problem tcpcc solves

Linux congestion control is normally selected by the kernel that owns a TCP
socket. That is straightforward on a machine where the operator controls the
kernel, can load the desired congestion-control implementation, and can change
`net.ipv4.tcp_congestion_control` or per-socket `TCP_CONGESTION` state.

A constrained VPS/container can be different. An OpenVZ-style guest may run an
ordinary application such as nginx and have enough network authority for TUN
and netfilter, yet still share a provider-controlled kernel whose TCP modules
and congestion-control policy cannot be changed by the tenant. If that outer
kernel does not provide BBR, changing the application does not make the public
connection use BBR.

`linux-tcp-cc` moves ownership of the **public TCP endpoint** into a small
userspace-hosted upstream Linux network stack. The application remains an
ordinary process on the outer host/container. The project therefore aims to
provide the Linux TCP implementation the operator wants without replacing the
provider's kernel and without reimplementing BBR, CUBIC, recovery, rate
sampling, or fq pacing.

The intended operator interface is deliberately proxy-like:

```text
sudo tcpcc \
  --listen 203.0.113.10:443 \
  --backend 127.0.0.1:443 \
  --cc bbr
```

Existing applications do not need to link against tcpcc or understand its
control ABI. They listen on the loopback backend as usual.

## The central architectural idea

There are **two different TCP connections** and two different kernel contexts.
Keeping them separate is the most important fact in the design.

```text
                         public TCP connection

remote client
    |
    | packets to --listen
    v
+------------------------- outer host/container -------------------------+
|                                                                        |
|  PREROUTING DNAT + conntrack                                           |
|             |                                                          |
|             | raw IPv4/IPv6 packets                                    |
|             v                                                          |
|        nonpersistent TUN                                               |
|             |                                                          |
|             | fd passed to hosted Linux                                |
|             v                                                          |
|  +-------------------- hosted upstream Linux ----------------------+   |
|  |                                                             |   |   |
|  |  TCP listener                                                |   |   |
|  |  TCP_CONGESTION = --cc                                      |   |   |
|  |  upstream CUBIC/BBR + recovery + rate sampling + fq          |   |   |
|  |             |                                               |   |   |
|  |             | accepted byte stream                           |   |   |
|  |             v                                               |   |   |
|  |       single-owner bridge dispatcher                         |   |   |
|  +-------------|-----------------------------------------------+   |
|                |                                                   |
|                | ordinary host socket                             |
|                v                                                   |
|        127.0.0.1:backend                                            |
|                |                                                   |
|                v                                                   |
|             nginx / app                                             |
|                                                                        |
+------------------------------------------------------------------------+

                         local backend TCP connection
```

The public connection terminates inside hosted Linux. Its congestion-control
algorithm is selected on the hosted listener and read back there before the
service is exposed. Accepted sockets inherit the listener's Linux TCP state in
the normal upstream socket path.

The backend connection is different: the bridge opens an ordinary outer-host
TCP socket to `127.0.0.1:<backend-port>`. Whatever congestion control that local
loopback socket uses is outside tcpcc's public-side contract.

This separation explains a critical product invariant:

> The outer host does not need to provide or select BBR for a tcpcc public
> listener to use hosted BBR.

The outer host is still required to provide the packet path that gets public
packets to the TUN device. In the current architecture that means usable TUN,
netfilter/firewall support, appropriate network authority, and forwarding for
the selected public address family.

## Why TUN and DNAT are used

The hosted Linux stack needs to see real IP packets, not a byte stream that has
already been terminated by the outer host. Otherwise the outer host TCP stack
would still own congestion control and tcpcc could not change the public
transport behavior.

A point-to-point TUN queue is enough because the boundary carries Layer-3 IPv4
or IPv6 packets. TAP/Ethernet, ARP, and a software Ethernet bridge would add
state that the product does not need.

The host installs an exact-match DNAT rule for the requested public address and
TCP port. The first packet is translated to the hosted TUN-side endpoint and
routed through the TUN queue. Conntrack remembers the mapping and performs the
reverse translation for replies emitted by hosted Linux.

The rule is deliberately narrow:

- exact public destination address;
- exact TCP destination port;
- no UDP interception;
- no broad redirect of unrelated host traffic;
- no implicit SNAT/masquerade policy.

Each tcpcc instance owns only its generated TUN and its instance-scoped
firewall resource.

## Runtime components and ownership

### Native supervisor

The installed `tcpcc` command is native C. The source-tree `./tcpcc` wrapper
executes the built native binary; production installation does not depend on
Python.

The native supervisor owns host lifecycle rather than payload forwarding. Its
responsibilities are:

1. parse and validate the operator contract;
2. perform read-only host prerequisite checks;
3. create and configure one exclusive nonpersistent TUN queue;
4. inspect ownership markers and reject unsafe stale/malformed state;
5. install one exact DNAT resource using the selected firewall backend;
6. `fork`/`execve` the hosted Linux executable;
7. establish the fixed-record control ABI over the child stdin/stdout;
8. pass the TUN queue as inherited fd 3;
9. configure the hosted L3 endpoint and public listener;
10. set/read back `TCP_CONGESTION` inside hosted Linux;
11. start the hosted service;
12. handle SIGINT/SIGTERM and aggregate runtime events; and
13. unwind owned resources in reverse order.

In steady state it does not accept public sockets and does not copy application
payload. It sleeps on event-driven process/signal state while the hosted
runtime owns network activity.

### Hosted Linux executable

The project builds Linux with `ARCH=tcpcc` as a normal `ET_EXEC` userspace
process. The architecture supplies the host syscall/runtime boundary needed to
run the selected upstream Linux networking code without booting a conventional
machine or replacing the outer kernel.

The hosted image contains the upstream TCP implementations needed by the
product, including CUBIC, BBR, TCP recovery/rate sampling, and fq. Project
specific code is concentrated under `linux-overlay/arch/tcpcc/` plus a small,
explicit generic patch surface.

### L3 TUN adapter

The hosted L3 adapter owns the raw packet boundary. It receives IP packets from
the inherited TUN fd and injects them into the hosted Linux networking stack;
transmitted SKBs are written back to the same TUN queue.

One budgeted packet-pump owner handles both directions. Readiness is event
driven, including temporary writable interest only when a nonblocking TUN write
actually returns `EAGAIN`. The design avoids a permanently armed writable event
and timer-based polling.

### Hosted service and bridge dispatcher

The public listener and accepted public Linux sockets stay inside hosted Linux.
One bridge dispatcher is the mutable owner of active flows. It handles public
socket readiness, loopback backend fd readiness, partial writes, half-close,
reset/cancel state, and terminal accounting.

The data path intentionally does **not** create forwarding threads per
connection. Active flow objects are dynamic, and 16-KiB direction buffers are
allocated only when a direction has data ready. All flows share a bounded
aggregate payload-buffer budget; when budget is unavailable, the dispatcher
stops reading and lets TCP/back-end readiness provide backpressure.

`--max-connections=0` is the default and means tcpcc adds no admission-policy
ceiling. A positive value is an operator-selected policy comparable to a proxy
`maxconn`; the handle encoding limit and CI capacity results are implementation
or validation boundaries, not the default product limit.

## Congestion-control ownership

The requested congestion control belongs to the hosted public listener:

```text
create hosted socket
    -> TCPCC_CONTROL_SET_CC(--cc)
    -> TCPCC_CONTROL_GET_CC
    -> exact comparison
    -> bind/listen
    -> SERVICE_START
```

`SET_CC` and `GET_CC` call the ordinary upstream Linux TCP socket-option paths.
If the hosted image cannot select the requested algorithm, startup fails at
this boundary.

The following outer-host state is therefore **not** a prerequisite for the
public connection:

- `net.ipv4.tcp_congestion_control == --cc`;
- the requested algorithm appearing in the outer
  `tcp_available_congestion_control` list; or
- the outer kernel having `tcp_bbr` loaded or compiled.

Conversely, forwarding is a real outer-host requirement of the current routed
TUN/DNAT data path. IPv4 public endpoints require `net.ipv4.ip_forward=1` and
IPv6 endpoints require `net.ipv6.conf.all.forwarding=1`. tcpcc diagnoses but
does not silently rewrite global policy.

## Host-resource lifecycle

Host mutation is transactional. Preflight and ownership inspection occur before
resource acquisition. After acquisition, every owned resource is journaled and
unwound in reverse order.

The TUN queue is created with exclusive, nonpersistent semantics. tcpcc never
adopts an existing interface. Closing the queue removes the interface and its
attached address/route state.

The firewall resource is instance-scoped. `nft-lib` is the default transport;
`nft-exec` and explicit iptables nft/legacy compatibility paths implement the
same ownership model. Backend selection is explicit. A failed firewall backend
must not silently fall through to another implementation.

Ownership markers include enough process identity to distinguish a live
instance from PID reuse. Stale or malformed marked resources block mutation and
produce operator-facing remediation rather than being automatically deleted.
Unrelated firewall state is not adopted.

On orderly shutdown tcpcc closes admission, allows active flows to drain for the
configured grace period, cancels only the remainder, stops hosted Linux,
removes the exact firewall resource, and closes the nonpersistent TUN. SIGKILL
cannot execute userspace firewall cleanup, so a surviving marked resource is
reported on the next startup rather than guessed away.

## Memory model

Guest-visible RAM capacity, host virtual address space, resident memory, and
connection admission are different quantities.

`--memory-mib=N` creates a contiguous anonymous guest arena and establishes the
hosted buddy allocator's capacity ceiling. The mapping uses `MAP_NORESERVE` and
is demand paged; setting a 512-MiB guest capacity does not eagerly consume
512 MiB of host RSS.

Guest pages proven free by Linux page reporting are batched and returned to the
host with `MADV_DONTNEED` from sleepable context. CI verifies that RSS rises
under load, materially falls after flows are reaped, and that the same hosted
process can reuse reclaimed pages for fresh bidirectional traffic.

The current architecture deliberately keeps a startup-sized contiguous
`FLATMEM` arena. M10.4 evaluated whether true online guest-memory growth was
justified. Existing 16,384-connection and repeated 8,192-connection evidence did
not demonstrate a capacity problem requiring `SPARSEMEM`/memory hotplug, so
online growth is **not** current planned behavior. If real deployments later
show that the guest-capacity ceiling is a product bottleneck, that should be a
new evidence-driven design change rather than assumed unfinished M10 work.

## CPU model

The architecture is designed for low idle cost and bounded active work. The
hosted kernel uses tickless idle rather than waking on a permanent 100-Hz
periodic tick. TUN work is coalesced and budgeted, and the bridge uses one
readiness-driven mutable owner rather than connection-scanning or per-flow
workers.

M11 CI exercises idle and small-packet behavior under both 25% and 50% cgroup
CPU quotas in addition to the existing throughput, capacity, signal-drain, and
lossless data-path gates.

## Address-family and backend boundaries

The public endpoint may be IPv4 or IPv6. The selected public family determines
the TUN endpoints, forwarding prerequisite, firewall family, hosted listener,
and hosted route.

The application backend is intentionally narrower today: it is an ordinary
IPv4 loopback endpoint under `127.0.0.1`. Extending the backend contract is a
separate product change; it should not be inferred merely because the public
side supports IPv6.

## What tcpcc is not

The following are useful non-goals because they prevent architectural drift:

- It is not an embedded-Linux project. `ARCH=tcpcc` exists to reuse upstream
  Linux networking semantics in a userspace-hosted runtime.
- It is not a new congestion-control implementation. Upstream Linux owns BBR,
  CUBIC, delivery-rate sampling, recovery, and fq behavior.
- It is not SOCKS5, HTTP CONNECT, or a general application proxy protocol.
- It is not a TAP/Ethernet virtual-network product; the production public path
  is L3 TUN.
- It does not require or silently change the outer host's TCP congestion-control
  policy.
- It does not use per-flow forwarding threads or a second hosted kernel to scale
  connection count.
- It does not interpret a benchmark pass count as a permanent product
  `max_connections` default.
- It does not currently provide online guest-memory hotplug.

## Source map

| Area | Primary source |
| --- | --- |
| Installed CLI / lifecycle supervisor | `native/tcpcc_cli.c`, `native/tcpcc_process.c` |
| Native fixed-record control client | `native/tcpcc_control.c` |
| Host TUN/firewall lifecycle | native supervisor/lifecycle sources and host helpers |
| Hosted architecture/runtime | `linux-overlay/arch/tcpcc/` |
| Hosted control operations | `linux-overlay/arch/tcpcc/kernel/control.c` |
| Hosted service/accept ownership | `linux-overlay/arch/tcpcc/kernel/service.c` |
| Stream bridge/dispatcher | `linux-overlay/arch/tcpcc/kernel/bridge.c` |
| L3 TUN netdevice path | `linux-overlay/arch/tcpcc/kernel/l3net.c` |
| Memory mapping/reclaim | `linux-overlay/arch/tcpcc/kernel/host.c`, `reclaim.c` |
| Linux internal API containment | compatibility units described by `docs/porting.md` |
| Production kernel selection | `config/tcpcc_defconfig` and build scripts |
| Integration/benchmark harnesses | `scripts/` and `.github/workflows/` |
| Legacy Python supervisor model | `tools/tcpcc_cli.py` (not installed production code) |

## Upstream maintenance boundary

The project intentionally minimizes its fork surface. The exact Linux source is
fetched from the pinned stable tag, the architecture overlay is applied, and
explicit generic patches are kept small and reviewable.

BBR, TCP rate sampling, Linux TCP recovery, and fq are protected upstream
behavior. Porting to another Linux series should adapt the `ARCH=tcpcc` and
compatibility boundary rather than editing those algorithms until the project
quietly becomes its own TCP fork. See `docs/porting.md` for the detailed
version-dependency map and mainline-canary process.

## Documentation model

`README.md` is the product front door. This file is the current architectural
source of truth. `docs/index.md` points to detailed current mechanism and design
history. Milestone documents are retained because they explain why constraints
exist and contain valuable CI evidence, but historical intermediate behavior
must not override the current architecture.

When a code change invalidates a statement here, update the documentation in
the same PR. The repository should contain enough product intent and design
state that a new human developer or coding agent can reconstruct the project
without relying on an old chat session.

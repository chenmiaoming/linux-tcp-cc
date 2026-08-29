# M8 server-ingress design

M8 turns the hosted Linux TCP stack into an inbound server-side TCP front end.
It is not a SOCKS5 or HTTP CONNECT proxy.

The target operator interface is:

```text
sudo tcpcc \
  --listen 203.0.113.10:443 \
  --backend 127.0.0.1:443 \
  --cc bbr
```

The public TCP connection terminates on a listener inside the hosted Linux
stack. `TCP_CONGESTION` is applied to that listener before `listen(2)`, and an
accepted socket must inherit the requested algorithm. A separate ordinary host
TCP connection carries the stream to the local backend; its congestion-control
choice is outside tcpcc's public-side contract.

### M8.4-M8.5 command contract

The repository launcher is `./tcpcc`. `sudo make install` installs the launcher
as `PREFIX/bin/tcpcc`, its private modules under `PREFIX/lib/tcpcc`, and the
validated hosted image as `PREFIX/libexec/tcpcc/vmlinux`. The default prefix is
`/usr/local`; `VMLINUX` can select another already-built hosted image. An
uninstalled checkout can instead pass `--kernel` or set `TCPCC_KERNEL`.

The three product arguments are mandatory and strictly parsed before any host
mutation. Public addresses are literal IPv4 or bracketed IPv6, ports are
1-65535, and the current backend boundary deliberately accepts only
`127.0.0.1`:

```text
--listen IPv4:PORT | [IPv6]:PORT
--backend 127.0.0.1:PORT
--cc ALGORITHM
```

The original M8 gate limited `--max-connections` to 8. M9.4 replaced that fixed
table with dynamic flows. M9.6 makes `0` the default, meaning that no admission
policy is applied; positive values remain an opt-in operator limit. The current
twenty-bit slot layout has a 1048575 handle-encoding boundary, which is an
implementation boundary rather than the default connection count.
`--shutdown-grace-period` controls how long signal shutdown waits for active
streams to finish before canceling them; it defaults to 5 seconds and accepts
0 through 300 seconds. Zero requests immediate cancellation after listener
closure.

The default internal point-to-point endpoints are `198.18.0.1` and
`198.18.0.2/32` for IPv4, or `fd00:198:18::1` and `fd00:198:18::2/128` for
IPv6. The public listener selects the family, and both TUN endpoints must match
it. Advanced deployments can set
`--tun-host-address`, `--tun-guest-address`, and `--tun-name`; those values are
also validated before lifecycle acquisition. The hosted stack installs a
device default route through `tcpcc0`, so return traffic for a public client
outside this internal prefix still reaches the host TUN and conntrack reverse
translation.

`--firewall-backend` selects exactly one of `nft-lib`, `nft-exec`, or
`iptables`; the default is `nft-lib`. The iptables transport additionally
accepts `--iptables-variant=iptables`, `iptables-nft`, or `iptables-legacy` and
uses the matching restore/save frontends. Selection is explicit and there is
no automatic fallback after compatibility, startup, or runtime failure.

The CLI launches the project-owned `ARCH=tcpcc` executable with only the owned
TUN fd inherited. It attaches L3, creates a hosted listener, applies and reads
back the requested `TCP_CONGESTION`, then uses nonblocking accept while no more
than the configured number of asynchronous bridge sessions run. Every accepted
child is read back to verify congestion-control inheritance before ownership
transfers to the bridge. The current dynamic service table has no admission
limit unless the operator supplies a positive `--max-connections` value.

Stdout is newline-delimited JSON with schema `tcpcc.runtime.v1`. The `ready`
record includes the exact public/backend endpoints, requested CC, TUN name,
hosted ifindex/PID, owned firewall resource, connection limit, and shutdown
grace period. `connection-opened` records expose the verified inherited CC and
current admission count. A completed session's `connection-closed` record
carries the actual terminal status plus byte counts, host readiness flags,
`EAGAIN` counts, and partial-write counts, including reset and cancellation
outcomes. A control-channel failure that prevents retrieval instead reports
that control status without inventing counters. Human diagnostics and hosted
kernel logs use stderr.

SIGINT/SIGTERM first close the hosted listener and emit `draining`. Existing
sessions continue until all finish or the monotonic grace deadline expires. A
deadline expiry emits `drain-timeout`, after which only remaining sessions are
canceled and joined. tcpcc then requests a clean hosted exit, removes DNAT, and
finally closes the nonpersistent TUN fd. Startup and runtime failures are
nonzero and still attempt every owned cleanup boundary.

### Historical M8.5 runtime hardening boundary

M8.5 originally proved eight generation-tagged session slots. Reaping a
terminal result releases exactly its slot; a later connection may reuse that
slot with a new generation, while stale handles remain invalid. Admission is
therefore recoverable rather than queueing accepted sockets outside the hosted
stack. M9.4 replaced this fixed table with dynamically allocated flows.

Each M8.5 session owned two 16-KiB bridge buffers, one per stream direction,
for a fixed 256-KiB bridge-buffer ceiling at eight sessions. The current bridge
allocates direction buffers on demand and shares an aggregate budget. Every
ordinary host backend socket requests 32 KiB for `SO_SNDBUF` and `SO_RCVBUF`
(Linux accounts each as a 64-KiB effective limit). Readiness-driven nonblocking
I/O and partial writes propagate pressure from a slow backend or public peer
without growing an application-level queue.

The original bridge-join control operation retains its existing success/error
ABI. A new append-only result-join operation always returns the complete
64-byte terminal snapshot once a session finishes; the snapshot itself holds
the terminal errno. This lets the CLI report byte and backpressure counters for
clean EOF, RST, and explicit cancellation without changing earlier callers.

The real-TUN gate fills all eight slots concurrently, verifies that a ninth
start returns `ENOSPC`, reaps them, and proves a replacement connection can use
a released slot. Separate backend-RST and public-RST cases must fail only their
own sessions while a survivor continues to a clean bidirectional half-close.
The privileged CLI matrix additionally runs four delayed 512-KiB flows, sends
SIGTERM at the configured admission limit, observes real host-send
backpressure, drains without cancellation, and verifies exact DNAT/TUN cleanup
through `nft-lib`, `nft-exec`, `iptables-nft`, and `iptables-legacy`.

## Data path

```text
remote client
    |
    | TCP to --listen
    v
host PREROUTING DNAT / conntrack
    |
    | raw IPv4 or IPv6 packets through TUN
    v
hosted Linux TCP listener (--cc)
    |
    | userspace byte-stream bridge
    v
host TCP socket to --backend
```

TUN is the default and only M8 data plane. The link is point-to-point IPv4 or
IPv6 and does not require Ethernet headers, ARP, or a bridge, so TAP adds
complexity without helping this product path. A future AF_PACKET backend can be
evaluated separately; it is not a prerequisite for the first usable release.

DNAT applies only to TCP packets whose destination exactly matches
`--listen`. A loopback backend such as `127.0.0.1:443` therefore does not enter
the public listener again. Conntrack performs the reverse translation for
packets emitted by the hosted stack.

## Host authority and lifecycle

The final CLI may create and configure its dedicated TUN interface and install
dedicated nftables/iptables DNAT rules. Those resources must have unique names,
be installed transactionally, and be removed on orderly shutdown or startup
failure. Existing interfaces and unrelated firewall rules must never be
rewritten.

Global sysctls are operator-managed prerequisites. In particular, tcpcc does
not write `net.ipv4.tcp_congestion_control`; deployment documentation and the
startup preflight tell the operator how to inspect and configure the required
state. The same non-mutating policy applies to forwarding-related global
sysctls. A failed prerequisite produces a precise diagnostic instead of a
silent host-wide change.

### Read-only host preflight

Preflight completes before tcpcc acquires a TUN fd or installs packet-steering
state. It reads procfs, inspects `/dev/net/tun`, and resolves required tools; it
does not invoke a command or open any mutation path. All checks are reported in
one deterministic `tcpcc.host-preflight.v1` document so operators see every
problem from one run.

| Stable check | Requirement | Expected state |
| --- | --- | --- |
| `cap.net_admin` | required | effective `CAP_NET_ADMIN` bit 12 |
| `device.tun` | required | character device with read/write access |
| `tool.ip` | required | iproute2 frontend on `PATH` |
| `library.nftables` | required by `nft-lib` | libnftables available to the dynamic loader |
| `tool.nft` | required by `nft-exec` | nftables frontend on `PATH` |
| `tool.iptables` | required by `iptables` | selected xtables frontend on `PATH` |
| `tool.iptables-restore` | required by `iptables` | matching restore frontend on `PATH` |
| `tool.iptables-save` | required by `iptables` | matching read-only save frontend on `PATH` |
| `sysctl.ipv4_forward` | required for IPv4 listener | `net.ipv4.ip_forward=1` |
| `sysctl.ipv6_forward` | required for IPv6 listener | `net.ipv6.conf.all.forwarding=1` |
| `sysctl.tcp_congestion_control` | required | value equals the requested algorithm |
| `sysctl.tcp_available_congestion_control` | required | requested algorithm is listed |
| `sysctl.rp_filter.all` | advisory | `net.ipv4.conf.all.rp_filter=0` |
| `sysctl.rp_filter.default` | advisory | `net.ipv4.conf.default.rp_filter=0` |

Required failures prevent lifecycle acquisition and include an operator
remediation. Reverse-path filtering is advisory because the correct setting
depends on the surrounding routing policy, but its observed value is never
hidden. tcpcc neither writes these sysctls nor treats a warning as permission
to change them.

The lifecycle ownership journal starts only after this report is green. It may
later own the newly opened nonpersistent TUN queue, configuration attached to
that interface, and a uniquely named firewall resource. Global sysctls and any
pre-existing interface, route, table, chain, or rule are outside the journal
and are never adopted for cleanup.

### Nonpersistent TUN transaction

The first acquired resource is one queue fd opened directly from
`/dev/net/tun` with `O_RDWR | O_NONBLOCK | O_CLOEXEC`. `TUNSETIFF` requests
`IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`: TUN supplies raw IPv4 or IPv6 packets
without an extra packet-information header, while the exclusive flag prevents
tcpcc from attaching to an existing interface. tcpcc never enables persistence
and never runs `ip tuntap add`.

An optional operator-supplied interface name is validated against Linux's
15-byte limit. If absent, tcpcc generates a collision-resistant `tcpcc...`
name and retries only `EBUSY` or `EEXIST` returned by the exclusive ioctl. A
requested name is attempted exactly once. Thus an existing interface is never
adopted, reconfigured, or made part of tcpcc's cleanup transaction.

After validating the exact name returned by the kernel, tcpcc invokes
iproute2 directly with argv arrays to add host/peer `/32` addresses for IPv4
or `/128` addresses for IPv6, set the validated MTU, and bring up only that
link. IPv6 additionally installs an explicit route to the guest `/128`, because
the peer address alone does not reliably create it. No shell is involved.
Failure at the ioctl, returned-name, address, route, MTU, or link-up boundary
immediately closes the fd; because the queue is
nonpersistent, Linux removes the partial interface and all state attached to
it.

The open queue fd is retained for later transfer to the hosted kernel through
an explicit inherited-fd list. Its `close` operation is idempotent and is the
sole normal TUN teardown mechanism. The ownership journal executes callbacks
once in reverse acquisition order, continues after individual cleanup errors,
and reports every failed callback. Consequently the later DNAT entry is
registered after the TUN and is removed before the final TUN fd is closed.

### Exact-match DNAT transaction

Packet steering is acquired only after the TUN queue is configured and entered
in the ownership journal. Every backend consumes the same validated exact-DNAT
description and returns an owned resource lease. Backend selection is explicit;
a failed backend never silently falls through to another implementation.

The two nft paths create one collision-resistant table in the matching `ip` or
`ip6` nftables family from a common command buffer. `nft-lib` submits it
in-process, while `nft-exec` invokes `nft --file -` without a shell. The batch
uses `create table`, whose exclusive semantics reject an existing name; `add
table` is deliberately forbidden because nftables permits it to reuse an
existing table.

The same atomic batch creates one base chain and one rule equivalent to:

```text
create table ip tcpcc_<instance>
add chain ip tcpcc_<instance> prerouting { type nat hook prerouting priority dstnat; policy accept; }
add rule ip tcpcc_<instance> prerouting ip daddr <listen-address> tcp dport <listen-port> counter dnat to <hosted-address>:<hosted-port>
```

For IPv6, the same template uses family `ip6`, selector `ip6 daddr`, and a
bracketed DNAT destination such as `[fd00:198:18::2]:443`.

The iptables path uses the matching `iptables*` or `ip6tables*` frontend,
exclusively creates `TCPCC_<instance>`, appends the owned
DNAT rule to that private chain, and appends one exact-match jump from
`nat/PREROUTING`. The two appends share one `iptables-restore --noflush`
transaction. A restore failure flushes and deletes only the newly created
private chain; normal cleanup deletes the exact jump before flushing and
deleting that chain. It never flushes `PREROUTING` or another shared chain.

Addresses, ports, and bounded resource identifiers are validated before a
firewall call. Subprocess transports use argv arrays and standard input; no
shell interprets either input. A rejected exclusive create is never adopted or
registered for cleanup. A successful lease deletes only its instance-scoped
resource, once, and reports cleanup failures through the journal.

The rule intentionally matches both the exact public IPv4 or IPv6 address and
exact TCP destination port. It does not redirect other addresses, UDP, or
another port. The NAT chain sees the first packet of a connection; conntrack
applies the stored translation to subsequent packets and reverses the hosted
source address and port on replies. tcpcc does not add a broad forwarding policy,
SNAT/masquerade rule, or sysctl write. Those host-wide routing and firewall
prerequisites remain operator policy.

The privileged lifecycle gate builds disposable client, router, and hosted
network namespaces. The router and hosted namespaces each own a real
nonpersistent TUN queue, with userspace relaying only their raw IP packets. A
TCP payload must therefore traverse exact DNAT and the TUN path in both
directions. For every backend, the gate rejects same-address/wrong-port and
same-port/wrong-address flows, verifies the owned rule counter and conntrack
original/reply tuples, rejects an existing requested resource, then proves
reverse cleanup removes DNAT before TUN while unrelated firewall state remains
byte-for-byte unchanged. Namespace-scoped test prerequisites are destroyed
with the test; they are not product behavior.

### Composed lifecycle and crash diagnostics

The complete host transaction runs five boundaries in strict order:

1. collect every read-only prerequisite result;
2. use the selected backend to list and classify marked tcpcc rules without
   modifying them;
3. ask that backend to dry-run the exact resource, rules, and ownership marker;
4. create, configure, and immediately journal the nonpersistent TUN queue;
5. create and immediately journal the exact DNAT resource.

A required preflight failure or unsafe ownership report stops before opening
`/dev/net/tun`. Failure after TUN acquisition closes that queue. Failure while
registering a newly acquired resource first closes the unregistered resource,
then rolls back earlier journal entries. If rollback itself fails, tcpcc keeps
the primary startup exception and reports every cleanup exception rather than
masking one with another.

The exact DNAT rule acquired by this composed path carries a versioned
comment:

```text
tcpcc.owner.v1 pid=<pid> start=<proc-start-time> tun=<interface>
```

Rule comments are used instead of table comments because rule-comment support
predates table-comment support and therefore keeps the host-kernel baseline
lower. The read-only nft scan uses JSON ruleset output and associates the
marker with its table. The iptables scan parses `iptables-save -t nat`, accepts
only one valid marker in a reserved private chain, and ignores unmarked
unrelated chains.

The process start time from `/proc/<pid>/stat` distinguishes an active owner
from PID reuse. At the next startup, a matching PID and start time is active
and may belong to another running tcpcc instance. A missing/mismatched process
is stale; an unsupported or invalid tcpcc marker is malformed. Stale and
malformed markers block mutation and include the exact table or private chain
plus an operator remediation. For iptables, remediation removes the exact
owned `PREROUTING` jump before the private chain. tcpcc never automatically
deletes a discovered resource. Unmarked resources outside the reserved naming
and marker protocol are ignored.

`SIGINT` and `SIGTERM` handlers only set an orderly-shutdown request. Normal
control flow removes DNAT, closes the TUN fd, and restores the prior handlers;
repeated requests and cleanup calls are harmless. `SIGKILL` cannot run
userspace cleanup: the kernel still removes the nonpersistent TUN when the
process fd closes, while the surviving marked firewall resource is detected
and reported at the next startup for explicit operator deletion.

### Firewall backend boundary

The lifecycle consumes a validated DNAT description and must not expose shell
text as its public API. Following Docker's split between firewall policy and
transport, the lifecycle implementation has three independently tested paths:

1. `nft-lib`: call `libnftables` in-process and submit one atomic batch;
2. `nft-exec`: invoke `nft -f -` without a shell and pass the same batch on
   standard input;
3. `iptables`: use argv-only `iptables` plus `iptables-restore --noflush`
   standard input for hosts that require the xtables compatibility path.

The two nft transports share table naming, ownership markers, stale-resource
classification, and rollback semantics. The iptables transport owns a unique
user chain plus one exact jump from `nat/PREROUTING`; cleanup removes that jump
before deleting the chain and never flushes a built-in or unrelated chain.
`iptables-nft` and `iptables-legacy` are separate mandatory CI matrix entries
against that transport.

CI must not treat the transports as interchangeable coverage. Every path has
its own unit and privileged namespace matrix covering exact destination and
port matching, successful reverse conntrack translation, existing-resource
collision, rejected install rollback, orderly signal cleanup, stale ownership
diagnosis, and preservation of unrelated firewall state. A path is not
release-eligible merely because another path passes.

Per-listener congestion control inside the hosted stack remains tcpcc's
responsibility and is selected by `--cc`.

## Delivery sequence

1. Prove real-TUN inbound listen/accept and CUBIC/BBR inheritance.
2. Replace the synchronous test control path with an asynchronous,
   multi-connection stream bridge to host backend sockets.
3. Add transactional TUN and DNAT lifecycle management plus read-only
   prerequisite checks.
4. Expose the stable `--listen`, `--backend`, and `--cc` CLI and run an
   end-to-end nginx-compatible test.
5. Harden concurrency, backpressure, half-close, reset, shutdown, recovery,
   resource limits, and long-duration behavior before packaging a release.

M8.1 covers only step 1. It deliberately validates the direction and socket
inheritance on which all later server-proxy work depends, without treating the
current serialized control ABI as a production stream transport.

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

## Data path

```text
remote client
    |
    | TCP to --listen
    v
host PREROUTING DNAT / conntrack
    |
    | IPv4 packets through TUN
    v
hosted Linux TCP listener (--cc)
    |
    | userspace byte-stream bridge
    v
host TCP socket to --backend
```

TUN is the default and only M8 data plane. The link is point-to-point IPv4 and
does not require Ethernet headers, ARP, or a bridge, so TAP adds complexity
without helping this product path. A future AF_PACKET backend can be evaluated
separately; it is not a prerequisite for the first usable release.

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
| `tool.nft` | required | nftables frontend on `PATH` |
| `sysctl.ipv4_forward` | required | `net.ipv4.ip_forward=1` |
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
that interface, and a uniquely named firewall table. Global sysctls and any
pre-existing interface, route, table, chain, or rule are outside the journal
and are never adopted for cleanup.

### Nonpersistent TUN transaction

The first acquired resource is one queue fd opened directly from
`/dev/net/tun` with `O_RDWR | O_NONBLOCK | O_CLOEXEC`. `TUNSETIFF` requests
`IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`: TUN supplies raw IPv4 packets without an
extra packet-information header, while the exclusive flag atomically prevents
tcpcc from attaching to an existing interface. tcpcc never enables persistence
and never runs `ip tuntap add`.

An optional operator-supplied interface name is validated against Linux's
15-byte limit. If absent, tcpcc generates a collision-resistant `tcpcc...`
name and retries only `EBUSY` or `EEXIST` returned by the exclusive ioctl. A
requested name is attempted exactly once. Thus an existing interface is never
adopted, reconfigured, or made part of tcpcc's cleanup transaction.

After validating the exact name returned by the kernel, tcpcc invokes
iproute2 directly with argv arrays to add the host `/32` and peer `/32`
point-to-point addresses, set the validated MTU, and bring up only that link.
No shell is involved. Failure at the ioctl, returned-name, address, MTU, or
link-up boundary immediately closes the fd; because the queue is
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
in the ownership journal. tcpcc creates one collision-resistant table in the
IPv4 nftables family through a single `nft --file -` invocation. The batch uses
`create table`, whose exclusive semantics reject an existing name; `add table`
is deliberately forbidden because nftables permits it to reuse an existing
table.

The same atomic batch creates one base chain and one rule equivalent to:

```text
create table ip tcpcc_<instance>
add chain ip tcpcc_<instance> prerouting { type nat hook prerouting priority dstnat; policy accept; }
add rule ip tcpcc_<instance> prerouting ip daddr <listen-address> tcp dport <listen-port> counter dnat to <hosted-address>:<hosted-port>
```

Addresses, ports, and the optional bounded table identifier are validated
before invoking nftables. The command is an argv array and the generated batch
is passed on stdin; no shell interprets either input. A rejected transaction
creates no partial table, chain, or rule and therefore acquires no cleanup
ownership. A successful lease deletes only `table ip tcpcc_<instance>`, once,
and reports a failed deletion through the journal.

The rule intentionally matches both the exact public IPv4 address and exact
TCP destination port. It does not redirect other addresses, UDP, or another
port. The NAT chain sees the first packet of a connection; conntrack applies
the stored translation to subsequent packets and reverses the hosted source
address and port on replies. tcpcc does not add a broad forwarding policy,
SNAT/masquerade rule, or sysctl write. Those host-wide routing and firewall
prerequisites remain operator policy.

The privileged lifecycle gate builds disposable client, router, and hosted
network namespaces. The router and hosted namespaces each own a real
nonpersistent TUN queue, with userspace relaying only their raw IP packets. A
TCP payload must therefore traverse exact DNAT and the TUN path in both
directions. The gate verifies the nft counter and conntrack original/reply
tuples, rejects an existing requested table, then proves reverse cleanup
removes DNAT before TUN while an unrelated table remains byte-for-byte
unchanged. Namespace-scoped test prerequisites are destroyed with the test;
they are not product behavior.

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

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
| `tool.nft` | required by the M8.3 transport | nftables frontend on `PATH` |
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

### Composed lifecycle and crash diagnostics

The complete host transaction runs five boundaries in strict order:

1. collect every read-only prerequisite result;
2. list and classify marked tcpcc nftables rules without modifying them;
3. ask nftables to dry-run the exact table, chain, rule, and ownership marker;
4. create, configure, and immediately journal the nonpersistent TUN queue;
5. create and immediately journal the exact DNAT table.

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
lower. The read-only scan uses nftables JSON ruleset output and associates the
marker with its containing table.

The process start time from `/proc/<pid>/stat` distinguishes an active owner
from PID reuse. At the next startup, a matching PID and start time is active
and may belong to another running tcpcc instance. A missing/mismatched process
is stale; an unsupported or invalid tcpcc marker is malformed. Stale and
malformed markers block mutation and include the exact table plus an operator
remediation. tcpcc never automatically deletes a discovered table. Unmarked
tables—even similarly named ones—are outside this ownership protocol and are
ignored.

`SIGINT` and `SIGTERM` handlers only set an orderly-shutdown request. Normal
control flow removes DNAT, closes the TUN fd, and restores the prior handlers;
repeated requests and cleanup calls are harmless. `SIGKILL` cannot run
userspace cleanup: the kernel still removes the nonpersistent TUN when the
process fd closes, while the surviving marked nftables table is detected and
reported at the next startup for explicit operator deletion.

### Firewall backend boundary

The lifecycle consumes a validated DNAT description and must not expose shell
text as its public API. Following Docker's split between firewall policy and
transport, the completed product has three independently tested paths:

1. `nft-lib`: call `libnftables` in-process and submit one atomic batch;
2. `nft-exec`: invoke `nft -f -` without a shell and pass the same batch on
   standard input;
3. `iptables`: use argv-only `iptables` plus `iptables-restore --noflush`
   standard input for hosts that require the xtables compatibility path.

The two nft transports share table naming, ownership markers, stale-resource
classification, and rollback semantics. The iptables transport owns a unique
user chain plus one exact jump from `nat/PREROUTING`; cleanup removes that jump
before deleting the chain and never flushes a built-in or unrelated chain.
`iptables-nft` and `iptables-legacy` are both exercised against that transport
when the CI runner exposes them.

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

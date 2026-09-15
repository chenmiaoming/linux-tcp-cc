# Real-host and OpenVZ qualification

This document defines the next deployment-qualification boundary after the
native multi-listener runtime. It is a current product-validation contract, not
a replacement for `ARCHITECTURE.md`.

## Goal

The remaining high-value question is no longer whether tcpcc can exercise TUN,
DNAT, hosted Linux TCP, BBR/CUBIC, multiple fixed forwards, memory reclaim, or
low-CPU operation in disposable CI namespaces. Those paths already have
privileged regression coverage.

The next question is whether a real constrained VPS/container exposes the exact
host capabilities that the current architecture requires. OpenVZ-style
providers differ in `/dev/net/tun`, effective capabilities, forwarding sysctls,
and nftables/iptables availability even when the guest user is root.

Qualification must therefore be possible before tcpcc mutates host networking.

## `tcpcc --check` contract

The native command will accept the normal intended runtime configuration plus
`--check`, for example:

```bash
sudo tcpcc \
  --check \
  --forward 203.0.113.10:443=127.0.0.1:8443 \
  --forward 203.0.113.10:8443=127.0.0.1:9443 \
  --cc bbr
```

`--check` uses the same native parser and validation rules as a real startup.
It is not a second shell/Python argument parser and does not translate legacy
`--listen` / `--backend` options.

A successful check validates the prerequisites that can be proven without
starting the hosted kernel:

- every `--forward` mapping and the one-TUN family/port constraints;
- effective `CAP_NET_ADMIN`;
- readable/writable character device `/dev/net/tun`;
- `net.ipv4.ip_forward=1` for IPv4 or
  `net.ipv6.conf.all.forwarding=1` for IPv6;
- `ip` availability;
- the selected firewall transport (`libnftables`, `nft`, or the selected
  iptables/ip6tables frontend plus its `*-save` ownership-inspection tool);
- the configured hosted image exists, is executable, and has the expected
  x86-64 little-endian static ET_EXEC shape; and
- existing tcpcc firewall ownership markers are safe to proceed past.

On success the command exits zero before signal setup, TUN creation, route
configuration, firewall creation, or hosted-process startup. A failure exits
nonzero with the same prerequisite diagnostic that would block normal startup.

The first implementation may emit a compact success record while retaining the
existing precise fail-fast diagnostics. If a real deployment shows that
operators need all failures in one invocation, the preflight representation can
be generalized later without changing the read-only boundary.

## Explicit non-checks

`--check` must not inspect the outer host's default or available TCP congestion
control as a prerequisite. The outer TCP stack is deliberately not the owner of
the public connection.

A read-only host check also cannot prove that the requested `--cc` is accepted
inside the hosted Linux image without executing that image. Normal startup
continues to prove that through hosted `SET_CC` followed by `GET_CC` before each
listener is exposed.

Likewise, `--check` does not claim that a public address is routable from the
Internet or that the provider's upstream firewall permits the port. Those are
end-to-end deployment properties and belong to the real-host smoke test.

## Ownership inspection must precede mutation

`ARCHITECTURE.md` requires both prerequisite checking and firewall ownership
inspection to happen before resource acquisition. The current native C path
needs one lifecycle correction here: stale/malformed `tcpcc.owner.v1` scanning
currently occurs inside firewall installation, after the TUN has already been
created and configured.

The qualification work must move that read-only ownership scan ahead of the
first TUN mutation. Normal startup and `--check` must consume the same scan.
Firewall installation may defensively revalidate if desired, but a known stale
or malformed tcpcc resource must never cause the supervisor to create a TUN
before rejecting startup.

The ordering after this change is:

```text
parse/validate CLI
  -> read-only host prerequisite checks
  -> read-only tcpcc firewall ownership inspection
  -> [--check: report success and exit]
  -> acquire/configure nonpersistent TUN
  -> acquire exact DNAT resources
  -> start hosted Linux and expose listeners
```

## Real-host qualification matrix

CI remains useful for deterministic regression, but this milestone is complete
only after evidence is collected from at least one real constrained VPS or
OpenVZ-style guest.

For each tested host, record:

1. provider / virtualization type and userspace distribution;
2. whether `/dev/net/tun` is present and usable;
3. effective `CAP_NET_ADMIN`;
4. selected IPv4/IPv6 forwarding value;
5. firewall backend and frontend versions;
6. `tcpcc --check` output and exit status;
7. a real application backend (initially nginx or an equivalent loopback TCP
   server) reached through one `--forward` mapping;
8. one multi-forward run when the provider permits two public ports;
9. SIGTERM drain and exact TUN/firewall cleanup; and
10. host RSS/PSS at ready, under load, and after reclaim for a 32- or 64-MiB
    hosted arena when the provider has a genuinely small memory limit.

The deployment smoke should verify the public connection rather than only the
loopback backend. Hosted BBR must work even when the outer host remains on CUBIC
or does not advertise BBR.

## Memory follow-up boundary

`docs/memory-footprint.md` intentionally stops low-risk static pruning. The
remaining plausible MiB-scale issue is guest free memory stranded in order-0 or
order-1 fragments below the current page-reporting minimum order of 2.

Do not change that reporting threshold speculatively. First collect buddy-order
telemetry and outer-host RSS/PSS from a real low-memory deployment. Only a
material stranded-free-page population justifies evaluating lower-order
reporting or batching.

## Release boundary

The currently published `v6.18.51` artifacts predate the multi-listener native
CLI merge. They remain immutable historical release artifacts. The next normal
6.18.y stable release should contain the current `--forward` contract and this
qualification work after its own post-merge validation; existing release tags
must not be rewritten merely to catch up with mainline.
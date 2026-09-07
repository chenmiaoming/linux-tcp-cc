# Repository guidance for coding agents

This file is a navigation map, not the project specification. The durable
project model is the human-readable documentation in this repository.

## Read first

1. `README.md` — problem, target environment, and operator contract.
2. `ARCHITECTURE.md` — current architecture and ownership boundaries. This is
   the current design source of truth.
3. `docs/index.md` — map of current documents and milestone/history records.
4. `docs/porting.md` — Linux-version compatibility and protected upstream
   boundaries.

Milestone documents contain valuable detail, but some sections describe
intermediate implementations. Do not infer the current architecture from one
old milestone in isolation.

## Project identity

TCPCC exists primarily so a constrained VPS/container, including OpenVZ-style
environments, can use upstream Linux congestion control such as BBR on its
**public TCP connection** even when the surrounding kernel cannot provide,
load, or select that algorithm.

```text
sudo tcpcc --listen ADDRESS:PORT --backend 127.0.0.1:PORT --cc ALGORITHM
```

The public TCP endpoint belongs to hosted Linux. The outer host provides the
TUN/netfilter packet path and a separate loopback TCP connection to the local
application. Mixing those two TCP legs is an architectural error.

Running tcpcc as root inside the target VPS/container is acceptable in the
current product model. Do not invent privilege separation as a product
requirement merely because the process is long-lived. What matters for
deployment is whether that container root actually has the required effective
network authority (`CAP_NET_ADMIN`), `/dev/net/tun`, firewall support, and
forwarding for the selected public address family.

This is not an embedded-Linux project, SOCKS/HTTP proxy, generic userspace
networking framework, or reimplementation of BBR/CUBIC.

## Code ownership map

- `native/` — installed production supervisor and host lifecycle.
- `linux-overlay/arch/tcpcc/` — hosted Linux architecture/runtime and data path.
- `tools/tcpcc_cli.py` — legacy Python supervisor/test model, not the installed
  production runtime.
- `scripts/` and `.github/workflows/` — tests, benchmarks, build and CI evidence.

## Boundaries that should not drift accidentally

- `--cc` is set and read back on the hosted public listener; outer-host BBR is
  not a prerequisite.
- The current public data plane is one nonpersistent TUN plus exact DNAT and
  conntrack; forwarding remains an outer-host prerequisite.
- The loopback backend TCP leg is separate from the public congestion-control
  contract.
- The hosted bridge has one mutable dispatcher owner, not per-flow forwarding
  threads.
- `--max-connections=0` means no tcpcc admission-policy limit; CI capacity is
  not a product default.
- Guest memory is demand-backed and reclaimable, but its guest-capacity arena
  is fixed at process startup; online memory hotplug is not current behavior.
- Resource cleanup may remove only state owned by that tcpcc instance.
- Firewall backend selection is explicit; do not add silent fallback.
- Upstream BBR, TCP rate sampling/recovery, and fq behavior are protected from
  casual project-local modification. Use the compatibility boundary in
  `docs/porting.md` for Linux-version drift.

When a change deliberately alters one of these boundaries, update
`ARCHITECTURE.md` in the same PR rather than leaving the new design only in code
or chat history.

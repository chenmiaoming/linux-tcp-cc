# Repository guidance for coding agents

This file is a navigation map, not the project specification. The durable
project model is the human-readable documentation, tests, and CI contracts in
this repository.

## Repository is project memory

Treat the repository as the durable memory of the project. Chat history,
private scratch notes, and an agent's remembered context are not sources of
truth and must not be required to reconstruct the current design.

Every change that introduces or changes a product behavior, ownership boundary,
ABI/CLI contract, lifecycle rule, performance policy, accepted/rejected design
decision, or important validation result must leave enough documentation in the
same pull request for a future maintainer or coding agent to recover:

1. what the current behavior is;
2. why that behavior was chosen;
3. which alternatives were rejected when that matters to future work;
4. where the implementation lives; and
5. which test or CI evidence protects the decision.

Do not leave a material design decision only in a PR discussion or chat. If code
and current-state documentation disagree, repair the documentation before the
change is considered complete.

Use the documentation layers deliberately:

- `README.md` — operator-visible product and supported environment;
- `ARCHITECTURE.md` — current composed architecture and ownership boundaries;
- `docs/runtime-lifecycle.md` — exact process/signal/boot/shutdown ordering;
- `docs/porting.md` — upstream-Linux maintenance and compatibility boundary;
- `docs/memory-footprint.md` — current memory evidence and accepted/rejected
  footprint decisions;
- focused current-state design docs — subsystem contracts that need more detail
  than `ARCHITECTURE.md`;
- milestone documents — mechanism, experiments, and historical reasoning.

Preserve useful historical evidence instead of mechanically rewriting it. Mark
superseded behavior as historical and point to the current contract. Update
`docs/index.md` whenever a new document becomes part of the project knowledge
map.

A feature is not finished merely because its code and narrow regression pass.
Its repository memory must also be current.

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
- One aggregate hosted service may own multiple public listeners; listener
  sockets, backend targets, and readiness are listener-local, while admission,
  statistics, drain, and stop are service-wide. There is still one service
  worker and one global bridge dispatcher.
- Multi-listener readiness must be event-driven and queue-based; do not replace
  it with periodic or O(number_of_listeners) polling/scanning.
- `--max-connections=0` means no tcpcc admission-policy limit; CI capacity is
  not a product default.
- Guest memory is demand-backed and reclaimable, but its guest-capacity arena
  is fixed at process startup; online memory hotplug is not current behavior.
- Resource cleanup may remove only state owned by that tcpcc instance.
- Firewall backend selection is explicit; do not add silent fallback.
- Upstream BBR, TCP rate sampling/recovery, and fq behavior are protected from
  casual project-local modification. Use the compatibility boundary in
  `docs/porting.md` for Linux-version drift.

When a change deliberately alters one of these boundaries, update the relevant
current-state documentation in the same PR rather than leaving the new design
only in code, a PR description, or chat history.

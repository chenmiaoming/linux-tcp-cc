# Documentation map

The repository documentation is organized around two different needs:

1. explain the **current product and architecture** without requiring knowledge
   of the development history; and
2. retain milestone design records and CI evidence that explain why the current
   constraints exist.

Start with the current-state documents. Use milestone documents for detail and
history, not as an excuse to resurrect an intermediate implementation that was
later replaced.

## Current sources of truth

### `README.md`

Product front door: the problem tcpcc solves, who it is for, the stable command,
host prerequisites, installation, and the shortest explanation of the data
path.

### `ARCHITECTURE.md`

Authoritative current system model. It defines:

- the constrained-VPS/OpenVZ use case;
- the distinction between the hosted public TCP connection and the ordinary
  loopback backend connection;
- TUN + exact DNAT/conntrack packet steering;
- native supervisor versus hosted-Linux ownership;
- congestion-control ownership;
- event-driven bridge/data ownership;
- memory and CPU models;
- lifecycle/resource invariants; and
- explicit non-goals.

When another document describes an old milestone state that conflicts with the
current architecture, this document wins and the stale text should be repaired.

### `docs/runtime-lifecycle.md`

Current process and lifecycle mechanics: supervisor/hosted-process ownership,
`signalfd` handling for SIGINT/SIGTERM, SIGPIPE policy, child `setsid()` and
`PDEATHSIG`, failure cleanup, and the post-PR-127 hosted-Linux boot-finalization
sequence from late initcall through `free_initmem()`, `SYSTEM_RUNNING`, readiness,
and long-lived runtime.

### `docs/porting.md`

Current Linux-version maintenance boundary: pinned upstream source, overlay and
patch reconstruction, compatibility units, both generic patch surfaces
(IPv6-address helper and post-kernel-init hook), protected upstream behavior,
and the mainline canary.

### `docs/releases.md`

Current release, packaging, LTS branch, stable-update, and artifact publication
contract.

## Detailed implementation records

These documents contain both useful current mechanism and the history of how it
was introduced. Sections that explicitly say "historical", "original", or name
an intermediate milestone should be read as design history.

### `docs/memory-footprint.md`

Static/runtime memory-footprint measurement contract and the current pruning
decision record. It contains the resolved-Kconfig audit, accepted #124/#126/#127
memory changes, rejected #123 allocator and #125 `-Os` experiments, the composed
current footprint, and the evidence threshold for any further memory work.

### `docs/m8-server-ingress-design.md`

Public server-ingress design, TUN/DNAT lifecycle, firewall ownership,
transactional cleanup, host preflight, and the original path from a hosted TCP
listener to a local backend. M9 later replaced the per-flow runtime/control
model and the installed native CLI now uses atomic `--forward LISTEN=BACKEND`
mappings instead of M8's historical separate `--listen` / `--backend` options;
use `ARCHITECTURE.md` and the M9 documents for the current contract.

### `docs/m8-high-bdp-iperf.md`

High-BDP/loss benchmark methodology comparing native and tcpcc CUBIC/BBR paths.
It is a benchmark contract, not the general product architecture document. The
document also marks the original automatic 4-MiB hosted `tcp_wmem` policy as
historical; current runs use the upstream RAM-derived TCP memory policy unless
an explicit override is added.

### `docs/m9-native-event-runtime.md`

Migration to the installed native C supervisor, fixed-record control ABI,
single-owner hosted bridge dispatcher, dynamic flows, admission policy, and
capacity gates. Early M9 subsections intentionally describe intermediate
compatibility states; current notes include the pidfd/control-pipe child-event
fallback and the later 32-MiB explicit memory minimum.

### `docs/m9-multi-listener-service.md`

Current detailed contract for one aggregate hosted service owning multiple
public listeners. It records listener-local backend ownership, service-wide
admission/stats/drain/stop policy, repeated `SERVICE_START` semantics, the
`MULTI_LISTENER` HELLO capability, and the event-driven FIFO ready queue used to
avoid listener-list polling while providing fair admission opportunity.

### `docs/m10-hosted-memory-lifecycle.md`

Demand-backed guest arena, page-reporting reclaim, RSS lifecycle measurement,
reuse/stability gates, and the decision boundary between reclaim and true online
guest-memory growth. Later static/lifecycle footprint decisions are recorded in
`docs/memory-footprint.md` rather than retroactively rewriting M10 history.

### `docs/m11-cpu-efficiency.md`

Tickless idle, coalesced TUN wakeups, budgeted packet pumping, and cgroup CPU
efficiency gates. Its active small-packet probe is also the guard used to reject
memory optimizations such as `-Os` when they materially increase packet-path CPU
cost.

## Historical plans

### `docs/m2-port-plan.md`

Historical bring-up plan for turning Linux 6.18 into the `ARCH=tcpcc` userspace
architecture. It explains early design intent and references, but it is not a
statement of the current runtime/product contract.

## Repository code map

For a code-oriented map, see the `Source map` section in `ARCHITECTURE.md`.
Several distinctions are especially important for new contributors and coding
agents:

- `native/` is the installed production supervisor path;
- `linux-overlay/arch/tcpcc/` is the hosted Linux architecture/runtime;
- `tools/tcpcc_cli.py` remains a legacy Python supervisor/test model and is not
  the installed runtime;
- `scripts/` contains tests and benchmark/build drivers, not necessarily
  production implementation; and
- `.github/workflows/` is a major part of the executable specification because
  privileged TUN/DNAT, IPv6, memory, CPU, signal/lifecycle, and high-BDP
  properties are validated there.

## Keeping the repository as project memory

A design decision that matters to future work should be recoverable from the
repository itself. In practice:

- update `ARCHITECTURE.md` when an ownership boundary or product invariant
  changes;
- update README when the operator contract or supported environment changes;
- keep exact process/signal/boot ordering in `docs/runtime-lifecycle.md`;
- keep footprint experiments and accepted/rejected memory decisions in
  `docs/memory-footprint.md`;
- keep detailed subsystem mechanism and measurements in the relevant focused or
  milestone design document, including multi-listener service scheduling in
  `docs/m9-multi-listener-service.md`;
- retain historical reasoning, but label superseded behavior instead of leaving
  it indistinguishable from current behavior; and
- prefer mechanical tests/CI for invariants that can be checked automatically.

This structure is intended to work for both human maintainers and coding agents:
the short entry points tell a reader where to look, while the detailed documents
remain normal engineering documentation rather than one monolithic instruction
file.

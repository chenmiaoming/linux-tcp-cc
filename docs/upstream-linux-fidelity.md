# Why tcpcc runs upstream Linux TCP

This document records a deliberate product choice: **linux-tcp-cc optimizes for
upstream Linux TCP fidelity before minimum footprint**.

The project does not exist because a smaller userspace TCP implementation is
impossible. It exists for operators who specifically want the Linux TCP
implementation they would have used on a machine where they controlled the
kernel, even though the surrounding VPS/container kernel cannot provide or
select that implementation.

## The fidelity goal

The public TCP endpoint is owned by the hosted Linux stack. The requested
congestion-control algorithm is selected on the hosted listener through the
ordinary Linux socket-option path and read back before the listener is exposed.

That keeps the following behavior in the upstream Linux networking
implementation rather than recreating it in project code:

- BBR and CUBIC congestion control;
- Linux delivery-rate sampling;
- TCP loss recovery;
- Linux TCP memory/autotuning behavior, except for explicit documented
  operator overrides;
- fq pacing behavior used by the hosted stack; and
- the normal Linux socket/listener/accepted-socket inheritance path.

The project therefore treats several networking sources as protected upstream
behavior during routine maintenance, including:

- `net/ipv4/tcp_bbr.c`;
- `net/ipv4/tcp_rate.c`;
- the Linux TCP recovery core; and
- `net/sched/sch_fq.c`.

Stable-series updates may legitimately change those files upstream. Such a
change is a reason for explicit review, not a reason to silently preserve the
old bytes forever.

## What “upstream Linux” does and does not mean

tcpcc is not an unmodified stock kernel image dropped into userspace.

Project-specific code is required to provide the hosted execution environment,
TUN-backed packet device, host syscall boundary, control API, lifecycle,
memory-return mechanism, and byte-stream bridge. Compatibility shims also adapt
the architecture to Linux API drift.

The maintenance rule is narrower and more useful:

> Keep tcpcc-specific changes around the architecture/runtime boundary, and do
> not fork TCP congestion-control and recovery semantics merely to make the
> userspace product work.

The exact upstream Linux tag/commit is pinned by the repository. Release tags
follow the corresponding Linux stable patch version, and CI checks protected
networking sources during stable-series updates.

## Why this matters

Reimplementing a named algorithm is not the same thing as reproducing the whole
transport behavior around it.

For example, BBR consumes delivery-rate and RTT observations produced by the
transport, interacts with pacing and congestion-window state, and runs alongside
Linux recovery and socket behavior. A small userspace implementation may be
perfectly valid, but matching one controller equation does not automatically
make the resulting endpoint equivalent to Linux TCP.

linux-tcp-cc chooses a different boundary: move ownership of the public socket
to Linux rather than move pieces of Linux TCP policy into another stack.

This reduces one class of semantic drift and makes upstream Linux behavior the
reference implementation by construction.

## The tradeoff

The cost of that choice is real.

A hosted Linux stack has a larger fixed footprint and a more complicated boot,
memory, and lifecycle model than a purpose-built small TCP endpoint. tcpcc has
therefore spent significant engineering effort on:

- demand-backed hosted memory;
- reclaim of guest pages proven free;
- reclaim of discardable init mappings;
- tickless idle;
- coalesced/budgeted packet processing;
- an event-driven bridge rather than per-flow forwarding threads; and
- explicit lifecycle and cleanup validation.

Those optimizations reduce the cost of hosting Linux; they do not change the
project's primary design objective.

## Relation to tcp-shift

The same maintainer also develops
[`tcp-shift`](https://github.com/chenmiaoming/tcp-shift), which deliberately
chooses the other side of this tradeoff.

tcp-shift terminates the public connection in lwIP and focuses on a small,
event-driven userspace endpoint. Its work includes RFC-oriented transport
qualification, explicit congestion-control integration, and transport recovery
such as RFC 8985 RACK-TLP.

The two projects therefore answer different questions:

| Project | Primary objective | TCP implementation boundary |
| --- | --- | --- |
| **linux-tcp-cc** | preserve upstream Linux TCP behavior | hosted upstream Linux owns public TCP |
| **tcp-shift** | minimize footprint and explicitly qualify transport behavior | lwIP + project transport/controller integration |

tcp-shift is evidence that the choice to host Linux is intentional rather than
an assumption that a compact implementation cannot be built.

## Non-claim: bare-metal equivalence

“Upstream Linux TCP” does not mean that every observed performance result must
match a bare-metal Linux host bit-for-bit or packet-for-packet.

The hosted stack runs behind a different packet device, memory capacity,
scheduler/runtime boundary, and outer DNAT/conntrack path. Those environmental
differences can affect timing and performance.

The fidelity claim is about **implementation ownership**:

- the public TCP socket is a Linux socket;
- the selected BBR/CUBIC implementation is Linux's implementation; and
- recovery/rate-sampling/pacing semantics remain owned by the corresponding
  Linux networking code rather than by a tcpcc reimplementation.

Performance claims still require scenario-specific measurement.

## Maintenance consequence

When considering a new optimization, ask this question first:

> Can this change stay outside upstream TCP semantics?

Optimizing host wakeups, memory residency, control/lifecycle plumbing, TUN
batching, or the byte-stream bridge fits the project well.

Replacing Linux recovery, modifying BBR to fit the hosted runtime, or adding a
project-specific approximation of Linux transport behavior should require a
much stronger design justification, because it weakens the reason this project
exists.

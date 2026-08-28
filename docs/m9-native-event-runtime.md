# M9 native event runtime

M9 removes Python from the installed runtime while keeping one hosted
`vmlinux`, one TUN queue, and one public endpoint. The target is a low-memory,
single-threaded, event-driven service: one owner mutates every connection and
therefore the data plane requires no application locks.

Python remains available as a compatibility path while the native path is
built and validated. It is removed from installation only after the C runtime
has equivalent lifecycle, fault-boundary, and real-TUN CI coverage.

## Process and data ownership

The native host executable is a lifecycle supervisor. It performs preflight,
creates the TUN queue, installs the exact DNAT transaction, launches the hosted
kernel, handles signals, and emits bounded aggregate diagnostics. It does not
copy payload bytes between sockets.

The hosted Linux executable remains an `ET_EXEC` process. The supervisor uses
`fork(2)` and `execve(2)`, connects control requests and responses to the
child's stdin and stdout, and makes the sole TUN queue available as child fd 3.
No part of `vmlinux` is dynamically linked or loaded with `dlopen(3)`.

Only descriptors 0 through 3 cross the exec boundary:

```text
native tcpcc supervisor
  epoll + signalfd + timerfd + pidfd
        |
        +-- stdin/stdout: fixed-record control ABI
        +-- fd 3: one nonpersistent TUN queue
        |
        `-- execve(vmlinux)
               |
               `-- hosted TCP + event-driven bridge
```

The TUN fd is passed once to `L3_ATTACH`. Packet ingress and egress then remain
between the host kernel's TUN implementation and the hosted network stack;
they never traverse the supervisor's event loop.

## Single-owner event model

The final steady-state service has two single-owner loops separated by the
control ABI:

- The native supervisor owns process state, signals, timers, host resources,
  and the control channel.
- One hosted bridge dispatcher owns the listener, accepted Linux sockets,
  ordinary host backend fds, per-flow state, and buffer accounting.

The hosted dispatcher is awakened by Linux socket callbacks and host epoll
readiness. It drains ready work in bounded batches and returns to the scheduler
when its work budget is exhausted. A connection state machine, rather than two
kthreads per connection, handles connect, read, partial write, half-close,
cancel, and terminal accounting.

No worker may mutate a flow owned by the dispatcher. Cross-boundary requests
are immutable messages, and terminal statistics are snapshots. This is the
lock-free property intended by "Redis-like": a single mutable owner, not an
assumption that the Linux TCP stack itself contains no locks.

## Capacity and backpressure

The existing eight-session table is a temporary M8 implementation limit, not
the M9 concurrency model. It must not simply be replaced by a larger compile-
time array because two fixed 16-KiB buffers per possible connection would make
idle connection cost grow unnecessarily.

M9 replaces it with dynamically allocated, generation-tagged flow objects and
three independent limits:

- `max_connections`: admission ceiling, configurable at runtime;
- `max_buffer_bytes`: aggregate payload-buffer budget;
- a small per-direction buffer cap allocated only when a flow carries data.

When the aggregate budget is exhausted, the dispatcher stops reading the
corresponding source. TCP receive windows and host socket readiness then carry
backpressure; the service does not grow an unbounded queue. Idle connections
retain state only and do not reserve both payload buffers.

Per-connection logging is disabled in the high-concurrency path. Counters are
aggregated and exported on a timer or explicit stats request so logging cannot
become the event loop's bottleneck.

## ABI migration

The shared header `asm/tcpcc_control_abi.h` is the only definition of the
fixed-record control protocol. `HELLO` is the first native operation and
returns the protocol version, feature bits, current bridge limits, and hosted
Linux release. New operations and feature bits are append-only within a
version.

The migration is deliberately split into mergeable gates:

1. Shared ABI, native exact-I/O client, `fork`/`execve` process boundary, and
   CI-only contract tests.
2. Hosted service operations (`SERVICE_START`, `SERVICE_DRAIN`, aggregate
   `SERVICE_STATS`) so the supervisor no longer polls accept/join per flow.
3. One hosted dispatcher; remove the two-kthreads-per-session implementation
   while retaining the eight-slot compatibility table for a focused parity
   gate.
4. Dynamic flow storage and buffer accounting; remove the eight-session
   limit, then add CI pressure gates.
5. Native preflight, TUN, firewall, signal, and rollback parity; switch the
   installed `tcpcc` entry point from Python to C.
6. CI pressure gates for idle connections, active throughput, slow peers,
   reset storms, and graceful drain. Published results include CPU, RSS,
   accepted/active/rejected counts, event-loop lag, and buffer high-water mark.

The first pressure gate finds capacity; it does not encode an arbitrary large
pass number. A later gate pins a conservative supported default below the
observed CI limit and verifies deterministic `EMFILE`, memory-budget, and
backlog behavior rather than allowing OOM or scheduler collapse.

## M9.2 hosted service ABI

M9.2 moves connection admission and terminal aggregation behind one hosted
service handle. `SERVICE_START` transfers an already configured listener to
the hosted service together with the loopback backend, admission ceiling, and
bounded accept batch. A listener socket callback wakes the service owner when
the accept queue changes; bridge completion wakes the same owner, which reaps
terminal results without a host-side polling interval.

`SERVICE_STATS` returns a fixed 88-byte aggregate snapshot. It includes
accepted, completed, rejected, active, and peak connections, byte totals,
accept `EAGAIN`, bridge-start and terminal failure counts, state, and the last
error. It deliberately carries no per-flow event stream. `SERVICE_DRAIN`
closes admission and waits for active flows, while `SERVICE_STOP` cancels any
remaining flows, releases the listener, and returns the terminal aggregate.

The M9.2 implementation still delegates payload forwarding to the M8 bridge,
including its eight-session ceiling and per-flow kthreads. This is an explicit
compatibility gate: the external service ABI and event-driven accept/reap
ownership are validated first, then M9.3 can replace the bridge internals with
one dispatcher without another supervisor/API migration.

## M9.3 single bridge dispatcher

M9.3 removes both forwarding kthreads from every bridge session. One hosted
dispatcher now owns all public-to-backend and backend-to-public state. Linux
socket callbacks mark public readiness, while the host runtime IRQ publishes
backend epoll readiness through a nonblocking queue and wakes the same
dispatcher. All reads and writes are nonblocking, retain partial-buffer state,
and use a bounded per-direction budget so one busy connection cannot monopolize
the single vCPU.

The existing generation-tagged eight-slot table and fixed buffers remain in
this gate. That deliberately keeps capacity allocation out of the data-plane
rewrite: existing reset isolation, half-close, backpressure, long-stream,
concurrent cancellation, lossless parity, and high-BDP CI checks can first
prove that the event state machine preserves M8 behavior.

## M9.4 dynamic flows and bounded buffers

M9.4 replaces both remaining fixed-capacity structures. Bridge slots are
allocated as the historical connection peak grows and retain their generation
after a flow is reaped, while active flow objects and hosted-service tracking
nodes exist only for live connections. The twelve-bit slot field provides an
encoding ceiling of 4095 simultaneous flows; that number was not treated as a
supported default until the M9.6 capacity gate subsequently exercised all
4095 slots.

The dispatcher consumes a deduplicated ready-flow queue instead of scanning
the encoding range or every idle connection. Each direction obtains its
16-KiB payload buffer only after source readiness and releases it after the
edge has been drained to `EAGAIN`, EOF, or a terminal condition. All flows
share a 256-KiB aggregate buffer budget. A flow that cannot reserve a buffer
stops reading its source and is requeued when another direction releases
budget, allowing TCP flow control to provide bounded backpressure.

The first M9.4 CI gate holds nine flows concurrently, proving that eight is no
longer a bridge limit while preserving generation reuse, reset isolation,
half-close, backpressure, and signal-drain coverage. Larger idle/active/slow-
peer discovery belongs to M9.6 and selects the supported default from measured
CPU and memory behavior rather than from the 4095-handle encoding ceiling.

## M9.6 capacity discovery and admission policy

The CLI defaults to the CI-validated current capacity of 4095 connections and
retains an explicit operator override comparable to a proxy `maxconn` setting.
This removes the historical eight-flow admission gate without claiming that a
handle encoding is the final production capacity.

The first discovery job drives the hosted `SERVICE_START` path directly so the
test harness does not create one polling loop or thread per flow. It grows one
listener and backend through 64, 256, 1024, 2048, and 4095 simultaneous
connections, exercises bidirectional data on 64 flows, and records aggregate
service counters, process RSS, virtual memory, host fd count, CPU ticks, and
bridge-buffer high-water. It reached 4095 active connections with zero rejects
or bridge-start failures; at that stage the hosted process used 27,280 KiB RSS,
held 4,101 host file descriptors, and consumed zero CPU ticks during the
250-millisecond idle sample.

The 4095 value is also the current twelve-bit bridge-handle encoding ceiling.
Because discovery reached it without admission or idle-resource failure, the
next capacity gate widens that opaque identifier and measures higher stages.
An ABI bit allocation must not become the product's final concurrency claim.

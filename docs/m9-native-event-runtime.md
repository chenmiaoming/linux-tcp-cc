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
3. One hosted dispatcher and dynamic flow storage; remove the eight-session
   limit and the two-kthreads-per-session implementation together.
4. Native preflight, TUN, firewall, signal, and rollback parity; switch the
   installed `tcpcc` entry point from Python to C.
5. CI pressure gates for idle connections, active throughput, slow peers,
   reset storms, and graceful drain. Published results include CPU, RSS,
   accepted/active/rejected counts, event-loop lag, and buffer high-water mark.

The first pressure gate finds capacity; it does not encode an arbitrary large
pass number. A later gate pins a conservative supported default below the
observed CI limit and verifies deterministic `EMFILE`, memory-budget, and
backlog behavior rather than allowing OOM or scheduler collapse.

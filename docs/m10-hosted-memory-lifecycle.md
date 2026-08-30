# M10 Hosted Memory Lifecycle, Demand-Backed Reservation, and Reclaim

M10.1 measures the complete memory lifecycle of the single hosted `vmlinux`,
M10.2 makes its host commit-accounting intent explicit, and M10.3 returns pages
that the guest buddy allocator has proved free to the host. Anonymous mappings
remain demand-paged: host resident memory (RSS) grows with pages actually
touched by the guest rather than with the configured guest-memory capacity,
and can now fall again after a workload spike.

## Memory Dimensions and Separation of Concerns

There are four distinct quantities tracked in the runtime:

1. **Guest-Visible RAM Capacity**: The number of PFNs initialized in the hosted
   Linux buddy allocator at boot (`--memory-mib=N`, default 128 MiB, 512 MiB
   in capacity CI).
2. **Host Virtual Address Space (`VmSize`)**: The anonymous private mapping
   arena backing the guest direct map (`tcpcc_physmem`).
3. **Host Resident Memory (`VmRSS` / `Anonymous`)**: Physical pages actually
   faulted into host RAM through demand paging as the guest touches them.
4. **Admission Policy**: Optional `--max-connections` ceiling (defaults to `0`
   for unlimited admission).

Configuring `--memory-mib=512` establishes an upper capacity ceiling for the
guest allocator and reserves a 512-MiB virtual arena; it does **not** eagerly
commit 512 MiB of host physical RAM.

## M10.2: Demand-Backed Reservation (`MAP_NORESERVE`)

In `linux-overlay/arch/tcpcc/kernel/host.c`, the initial anonymous arena mapping
uses:

```c
long ret = tcpcc_host_syscall6(TCPCC_HOST_NR_MMAP, 0, (long)len,
			       TCPCC_HOST_PROT_READ | TCPCC_HOST_PROT_WRITE,
			       TCPCC_HOST_MAP_ANON_FLAGS,
			       -1, 0);
```

The flag set lives in `asm/host_mman.h`, which is shared with the native
compile-time contract test so the production call and its test cannot silently
use different flag definitions.

Key invariants:

- The arena mapping is private, anonymous, contiguous, and read/write.
- `MAP_NORESERVE` suppresses reservation accounting when the host permits
  overcommit (`vm.overcommit_memory=0` or `1`). Linux deliberately ignores the
  flag in strict mode (`vm.overcommit_memory=2`), so an arena can still be
  rejected there when the host commit limit is insufficient.
- No eager prefaulting (`MAP_POPULATE`) or arena-wide zeroing is performed.
- Host physical pages are faulted in lazily on demand when the hosted kernel
  allocates and writes to them.

## M10.3: Safe Batched Guest-Free Page Reclaim

`CONFIG_PAGE_REPORTING` is the ownership boundary. Its delayed work isolates
pages from the buddy free lists before invoking the tcpcc provider, and puts
them back only after the provider returns. The provider therefore never
infers page ownership from host RSS, access recency, bridge counters, or TCP
state. PFN zero and every reserved or allocated page are absent from the buddy
free lists and cannot reach the callback; tcpcc also checks every supplied PFN
against the managed arena before crossing the host boundary.

The reporting provider in `arch/tcpcc/kernel/reclaim.c` has these properties:

- reporting starts two seconds after a qualifying free event through the
  generic freezable workqueue, so host syscalls run in sleepable process
  context rather than IRQ, softirq, spinlock, or allocator atomic context;
- the minimum reporting order is 3 (32 KiB), avoiding an advisory call for
  every order-0 page;
- each generic batch contains at most 32 entries; tcpcc sorts those entries by
  guest PFN, coalesces adjacent ranges, and caps each host advisory call at
  16 MiB;
- the provider calls `madvise(MADV_DONTNEED)` only on ranges isolated by page
  reporting. For a private anonymous host mapping, a later guest access faults
  in a zero-filled page, preserving allocator isolation and normal Linux page
  reuse semantics;
- the generic `PageReported` bit suppresses repeat discard of an unchanged
  free block and is cleared by the buddy allocator when that block is
  allocated again;
- `EINTR` is retried inside the host wrapper. Any other advisory error is
  recorded once and asynchronously unregisters the provider. `ENOSYS` and
  `EINVAL` are classified as unsupported; other failures are classified as
  failed. In every case memory remains valid guest RAM and TCP service
  continues without a retry loop.

The architecture selects exactly one additional production symbol,
`CONFIG_PAGE_REPORTING`. The existing CI ceilings remain unchanged at 112
enabled symbols, a 3.25 MiB `vmlinux`, and no `.eh_frame`; M10.3 does not raise
those gates.

The append-only `RECLAIM_STATS` control operation exposes monotonic aggregate
counters rather than per-page or per-flow events:

- bytes supplied by page reporting;
- bytes successfully discarded by the host;
- callback batches and bounded host ranges;
- bytes in the failed callback, advisory failure count, last error, and state;
- configured minimum order and maximum host range size.

These counters distinguish a successful host discard from an RSS fluctuation.
They do not claim that all guest TCP objects have reached their terminal state.

### Reclaim CI Gate

The 512 MiB / 16,384-flow lifecycle job retains the M10.1 samples and adds a
bounded 120-second reclaim observation after synchronous bridge teardown. It
requires all of the following:

1. the load grows anonymous RSS by at least 16 MiB over the ready sample;
2. successful discard bytes increase after the final active-flow sample;
3. anonymous RSS falls to at most the ready value plus half of the measured
   load-induced delta;
4. two post-reclaim idle samples are recorded;
5. 64 fresh bidirectional IPv4 flows pass through a new listener in the same
   process, while IPv6 public-endpoint CI executes a second verified flow after
   crossing the generic page-reporting delay.

The report publishes every one-second reclaim sample, its computed target,
discard delta, elapsed time, and recovered-delta ratio. The ratio is tied to
the same process's ready and peak samples rather than an exact runner-specific
RSS number. The gate does not require RSS to return exactly to boot level:
TCP timers, orphaned sockets, allocator metadata, and caches may remain live.
The window covers the observed exponential TCP close/orphan timer cadence; it
does not shorten those timers or treat bridge teardown as transport quiescence.

## M10.1: Complete Memory Lifecycle Measurement

The capacity discovery harness (`scripts/run-tcpcc-capacity-discovery.py`)
records host memory telemetry across five distinct lifecycle phases:

1. **`ready_sample`**: Captured immediately after the hosted kernel completes
   boot, attaches the TUN interface, configures the BBR listener, and starts
   the hosted service—before any public connection arrives.
2. **`stages`**: Captured at each connection level (64, 256, 1024, 2048, 4095,
   8192, 16384 connections), including bidirectional active probe results,
   service counters, and idle CPU tick delta.
3. **`post_drain_sample`**: Captured after the first service is stopped and all
   of its bridges have been synchronously reaped (`active_connections == 0`).
   Stopping the service is deterministic even when thousands of TCP close
   handshakes would not naturally finish inside a short CI timeout; it does not
   stop or restart the hosted kernel process.
4. **`post_drain_idle_samples`**: Captured across two bounded idle windows (0.5
   seconds each) to preserve the immediate post-bridge residency and CPU
   observation introduced by M10.1.
5. **`reuse_sample`**: Starts a fresh listener and service on the dedicated
   lifecycle-test port 18501 inside the same hosted kernel, then executes 64
   bidirectional flows with payload verification. A distinct port avoids making
   this memory test depend on TCP's previous-connection port reuse timing. It
   proves that the runtime remains reusable after the capacity service is fully
   torn down. Under M10.3 it runs after the bounded reclaim gate.

M10.3 appends `reclaim_samples`, `reclaim_result`, and
`post_reclaim_idle_samples`; it does not rename or reinterpret the earlier
schema fields.

### Process Telemetry Metrics

Process metrics inspect `/proc/<pid>/smaps_rollup` (with `/proc/<pid>/status`
and `/proc/<pid>/stat` fallback) and record:

- `rss_kib`: Resident Set Size (`Rss` / `VmRSS`)
- `pss_kib`: Proportional Set Size (`Pss`), or `null` when rollup data is not
  available
- `private_dirty_kib`: Private dirty pages (`Private_Dirty`), or `null` when
  rollup data is not available
- `anonymous_kib`: Anonymous resident pages (`Anonymous` / `RssAnon`), or
  `null` when neither source exposes the value
- `virtual_kib`: Virtual memory size (`VmSize`)
- `threads`: Process thread count (always 1 for the hosted kernel)
- `host_fds`: Number of open host file descriptors
- `cpu_ticks`: Cumulative user + system CPU ticks
- `smaps_rollup_available` and `rss_source`: make fallback provenance explicit

`/proc/<pid>/status`, `/proc/<pid>/stat`, and `/proc/<pid>/fd` are required
inputs. Read failures abort the measurement rather than being emitted as
plausible zero-valued telemetry. A failed capacity run preserves all lifecycle
samples collected before the error in its JSON artifact.

The resulting `tcpcc.capacity-discovery.v1` JSON artifact maintains append-only
compatibility while exposing detailed memory profiles across all stages.

## Bridge Drain Is Not TCP Quiescence

`post_drain_sample.service.active_connections == 0` means that the hosted
service has synchronously stopped and reaped every bridge session. It does not
mean that every underlying guest TCP control block has completed its close
state machine or that its slab pages are already free in the buddy allocator.

The first successful M10.1 capacity artifact made this distinction visible:

- RSS was about 72.1 MiB with 16,384 active flows and about 86.5 MiB immediately
  after service teardown;
- the two 0.5-second post-drain windows consumed 10 and 3 CPU ticks;
- the guest log emitted bounded `TCP: too many orphaned sockets` warnings while
  the second service nevertheless completed its 64-flow reuse probe.

These samples are the immediate post-bridge baseline, not a reclaim-success
threshold. The M10.3 implementation distinguishes these phases:

1. all bridge sessions reaped;
2. bounded TCP orphan/close-state quiescence;
3. guest-free pages reported and discarded by the host;
4. a fresh traffic pass proving safe reuse.

The reclaim gate never requires the page reporter to discard memory still
owned by TCP timers or orphaned sockets: such pages cannot be isolated from a
buddy free list. The bounded observation reports the guest log alongside RSS
and reclaim counters so orphan pressure remains visible separately.

## Capacity, Host Policy, and Online Growth

Reclaim changes residency, not guest-visible capacity. `--memory-mib=N` still
sets the contiguous guest arena and buddy allocator ceiling; it does not
reserve or eagerly consume `N` MiB of host RAM. The default remains 128 MiB and
`--max-connections=0` remains unlimited admission. A host cgroup, address-space
rlimit, strict overcommit policy, or physical memory pressure can still make a
host mapping or later page fault fail independently of the project admission
policy.

An advisory reclaim failure never converts into a connection limit and never
invalidates already mapped RAM. True one-way online growth is separate M10.4
work because it would change the guest allocator's capacity and likely the
current `FLATMEM`/contiguous direct-map model; `MADV_DONTNEED` deliberately does
neither.

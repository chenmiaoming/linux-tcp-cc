# M10 Hosted Memory Lifecycle and Demand-Backed Reservation

M10 makes the single hosted `vmlinux` behave like an ordinary low-footprint
server process from the host's perspective. Host resident physical memory (RSS)
grows dynamically with actual TCP workload rather than with a statically
configured guest-memory size.

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
			       TCPCC_HOST_MAP_PRIVATE | TCPCC_HOST_MAP_ANONYMOUS |
			       TCPCC_HOST_MAP_NORESERVE,
			       -1, 0);
```

Key invariants:
- The arena mapping is private, anonymous, contiguous, and read/write.
- `MAP_NORESERVE` prevents eager swap/memory reservation accounting on hosts
  configured with strict overcommit policies (`vm.overcommit_memory=2`).
- No eager prefaulting (`MAP_POPULATE`) or arena-wide zeroing is performed.
- Host physical pages are faulted in lazily on demand when the hosted kernel
  allocates and writes to them.

## M10.1: Complete Memory Lifecycle Measurement

The capacity discovery harness (`scripts/run-tcpcc-capacity-discovery.py`)
records host memory telemetry across five distinct lifecycle phases:

1. **`ready_sample`**: Captured immediately after the hosted kernel completes
   boot, attaches the TUN interface, configures the BBR listener, and starts
   the hosted service—before any public connection arrives.
2. **`stages`**: Captured at each connection level (64, 256, 1024, 2048, 4095,
   8192, 16384 connections), including bidirectional active probe results,
   service counters, and idle CPU tick delta.
3. **`post_drain_sample`**: Captured immediately after all client and backend
   sockets are closed and the hosted service confirms `active_connections == 0`.
4. **`reclaim_samples`**: Captured across two bounded idle windows (0.5 seconds
   each) to observe quiescent CPU usage and memory residency.
5. **`reuse_sample`**: Executes a second pass of 64 bidirectional flows with
   payload verification to prove that previously allocated/reclaimed pages
   are safely reusable without memory corruption or stale data.

### Process Telemetry Metrics

Process metrics inspect `/proc/<pid>/smaps_rollup` (with `/proc/<pid>/status`
and `/proc/<pid>/stat` fallback) and record:

- `rss_kib`: Resident Set Size (`Rss` / `VmRSS`)
- `pss_kib`: Proportional Set Size (`Pss`)
- `private_dirty_kib`: Private dirty pages (`Private_Dirty`)
- `anonymous_kib`: Anonymous resident pages (`Anonymous` / `RssAnon`)
- `virtual_kib`: Virtual memory size (`VmSize`)
- `threads`: Process thread count (always 1 for the hosted kernel)
- `host_fds`: Number of open host file descriptors
- `cpu_ticks`: Cumulative user + system CPU ticks

The resulting `tcpcc.capacity-discovery.v1` JSON artifact maintains append-only
compatibility while exposing detailed memory profiles across all stages.

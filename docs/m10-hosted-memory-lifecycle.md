# M10 Hosted Memory Lifecycle and Demand-Backed Reservation

M10.1 measures the complete memory lifecycle of the single hosted `vmlinux`,
and M10.2 makes its host commit-accounting intent explicit. Anonymous mappings
were already demand-paged: host resident memory (RSS) grows with pages actually
touched by the guest rather than with the configured guest-memory capacity.
Returning guest-free pages to the host is separate M10.3 work and is not
implemented here.

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
   seconds each) to establish the pre-reclaim residency and quiescent-CPU
   baseline for M10.3.
5. **`reuse_sample`**: Starts a fresh listener and service on the dedicated
   lifecycle-test port 18501 inside the same hosted kernel, then executes 64
   bidirectional flows with payload verification. A distinct port avoids making
   this memory test depend on TCP's previous-connection port reuse timing. It
   proves that the runtime remains reusable after the capacity service is fully
   torn down; it does not claim that host pages have already been discarded.

### Process Telemetry Metrics

Process metrics inspect `/proc/<pid>/smaps_rollup` (with `/proc/<pid>/status`
and `/proc/<pid>/stat` fallback) and record:

- `rss_kib`: Resident Set Size (`Rss` / `VmRSS`)
- `pss_kib`: Proportional Set Size (`Pss`), or `null` when rollup data is not
  available
- `private_dirty_kib`: Private dirty pages (`Private_Dirty`), or `null` when
  rollup data is not available
- `anonymous_kib`: Anonymous resident pages (`Anonymous` / `RssAnon`)
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

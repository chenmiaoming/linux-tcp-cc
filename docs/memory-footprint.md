# TCPCC memory-footprint measurement

Memory-footprint work must distinguish static linked-image size, guest-visible
memory ownership, and outer-host physical charging. A reduction in one layer is
not evidence that the others fell by the same amount.

The CI baseline intentionally records the fully resolved `ARCH=tcpcc`
configuration and linked `vmlinux` footprint so later pruning changes can be
compared against stable artifacts.

The architecture workflow publishes:

- `tcpcc-final.config` — the complete resolved Kconfig output;
- `tcpcc-enabled.config` — sorted `CONFIG_*=y/m` entries; and
- `tcpcc-arch.env` — config hash and enabled-symbol count.

The final-link workflow additionally publishes:

- GNU `size` output and ELF per-section sizes;
- the full symbol-size table plus the 40 largest linked symbols;
- `tcpcc-footprint.md`, which summarizes the comparable static metrics; and
- the same final config and enabled-symbol list used by the architecture stage.

Later memory-reduction pull requests should state the before/after static
metrics from these artifacts. Changes intended to reduce real low-memory VPS
usage must still be qualified separately with hosted runtime telemetry and the
outer container/hypervisor physical-memory accounting; static ELF savings alone
are not a runtime-memory result.

## Current decision summary

The September 2026 pruning pass established a useful stopping point for
low-risk memory work:

| Change | Decision | Main result |
| --- | --- | --- |
| PR #123 `CONFIG_SLUB_TINY` | rejected | lower startup RSS but much worse sustained/reclaim floor under high connection count |
| PR #124 reclaim loopback selftest buffers | merged | removes 192 KiB of process-lifetime `.bss`; improves M10 peak/floor behavior |
| PR #125 `CONFIG_CC_OPTIMIZE_FOR_SIZE` | rejected | saves about 560 KiB `.text` but adds roughly 20–25% CPU time in the active small-packet M11 probe |
| PR #126 shrink L3 RX scratch to MTU sentinel | merged | removes about 62.5 KiB permanent `.bss` without packet-path behavior change |
| PR #127 finish kernel init lifecycle | merged | reclaims the 96 KiB host-mapped init image before runtime readiness |

The accepted changes target memory that is provably temporary, oversized, or
init-only. The rejected changes demonstrate the current policy: do not trade a
connection-heavy runtime's allocator behavior or packet hot-path CPU efficiency
for a modest static saving.

On the pre-pruning Linux 6.18.51 baseline, GNU/ELF footprint reporting showed
323,489 bytes of `.bss`. After the loopback selftest and L3 scratch reductions,
the composed production image reports 62,817 bytes of `.bss`, a reduction of
about 80.6%. PR #127 is intentionally different: it barely changes static ELF
size, but removes a 96 KiB resident host ELF mapping after boot.

The resolved production configuration remains 116 enabled `CONFIG_*=y/m`
symbols across these accepted footprint changes.

## First resolved-Kconfig audit

The Linux 6.18.51 baseline resolves to 116 `CONFIG_*=y/m` symbols, but that
number is not a count of optional product features. Many entries are compiler,
architecture, or dependency capability symbols and carry no independently
removable runtime subsystem.

Several apparently removable entries are also not normal defconfig choices:

- `BPF` is selected by upstream `NET`;
- `DEBUG_KERNEL` is selected by upstream `EXPERT`;
- `NET_RX_BUSY_POLL` is a hidden upstream networking symbol that defaults on in
  this configuration; and
- `PAGE_MAPCOUNT` can only be inverted through the experimental
  `NO_PAGE_MAPCOUNT` option and does not remove the fixed page-type/mapcount
  storage from `struct page`.

TCPCC already disables modules, SMP, BPF user-facing facilities, io_uring,
block, proc/sysfs, TTY, USB, wireless, KALLSYMS and the normal debug machinery,
while using `BASE_SMALL`, `TINY_RCU`, a 4 KiB printk data ring and linker dead
code/data elimination. The audit therefore does not justify adding generic
Linux patches merely to force hidden dependency symbols off.

In particular, upstream `CONFIG_NET` unconditionally selects the small base
`CONFIG_BPF` core. The production config still keeps `CONFIG_BPF_SYSCALL`, BPF
JIT facilities, and higher-level eBPF features disabled. Removing the remaining
base interpreter would require generic networking surgery for a comparatively
small text saving, so it is not a current footprint target.

## Rejected SLUB_TINY experiment

PR #123 tested `CONFIG_SLUB_TINY` as one isolated allocator-policy change. It
reduced idle startup RSS by about 2 MiB but materially worsened the sustained
high-connection memory floor. In the 512 MiB M10 test, the post-reclaim
anonymous footprint moved from 40,320 KiB to 63,100 KiB and the six-round final
floor from 46,036 KiB to 70,708 KiB. Half-recovery was no longer observed within
the 120 second window. The linked image was effectively unchanged (+209 bytes
of GNU allocated size). The experiment was therefore closed without merging.

This is an important constraint for later work: TCPCC's connection-heavy
workload benefits from normal SLUB partial-slab behavior, so lower idle allocator
metadata is not automatically a lower production memory footprint.

## Reclaim temporary loopback selftest buffers

The baseline symbol report identified three 64 KiB arrays used only by the M4.1
loopback TCP startup stress test. They accounted for 192 KiB of process-lifetime
`.bss` even though their contents were dead once the selftest passed.

PR #124 replaced those static arrays with order-4 guest allocations created
immediately before M4.1 and returned to the guest allocator when the selftest
completes. The existing page-reporting path accepts order >= 2 frees, so the
three temporary order-4 ranges can subsequently be discarded from host backing
while the production runtime continues. The M4.1 workload itself remains 16
rounds of 64 KiB in each direction.

The change reduced `.bss` by 196,640 bytes. In the 512 MiB M10 run it also
reduced the 16,384-connection anonymous peak by about 2.8 MiB, lowered the
post-reclaim floor, and shortened the observed half-recovery time from roughly
53 seconds to roughly 7 seconds without reducing capacity.

The link validation keeps a permanent-`.bss` drift guard so later diagnostics
cannot silently reintroduce large process-lifetime test buffers.

## Rejected optimize-for-size experiment

PR #125 tested `CONFIG_CC_OPTIMIZE_FOR_SIZE` (`-Os`) in isolation. The static
saving was real: ELF `.text` fell from about 1.94 MiB to about 1.38 MiB, a
reduction of approximately 560 KiB, and ready RSS/PSS fell by roughly the same
amount.

The active M11 small-packet probe, however, regressed from the normal
approximately 0.17 CPU-s range to repeated 0.21–0.22 CPU-s results. That is
roughly 20–25% more CPU time for the same fixed amount of active packet work.
On an uncapped host that can appear as higher CPU utilization; near an OpenVZ or
cgroup CPU quota it instead translates into throttling, latency, or lower packet
rate.

The experiment was closed without merging. A smaller executable is not enough
to justify intentionally weakening compiler optimization on the production
packet hot path.

## Size the L3 RX scratch to the MTU sentinel

The original L3 receive scratch buffer was 65,535 bytes, a conservative maximum
IPv4-packet-sized allocation inherited from early bring-up. The production TUN
and hosted netdevice both use a 1500-byte MTU, and no TUN packet-info or vnet
header is enabled.

PR #126 changes the scratch buffer to `TCPCC_L3_MTU + 1`, currently 1501 bytes.
The extra sentinel byte is intentional: Linux TUN short reads can truncate a
larger packet to the userspace buffer length, so a 1500-byte buffer could make
an oversized frame appear exactly MTU-sized. A 1501-byte read preserves the
existing `len > dev->mtu` rejection path for an oversized frame.

The change reduces permanent `.bss` by about 64,032 bytes with no configuration
change. Real-TUN validation continues to exercise an exact-MTU 1500-byte IPv4
packet and an oversized case.

After PR #124 and PR #126 compose, the large project-owned permanent arrays are
no longer the dominant `.bss` problem. Remaining project globals are small; any
future large memory win is more likely to come from runtime page/slab behavior
than from another obvious static array.

## Reclaim the hosted init image

Before PR #127, the production control runtime blocked inside a synchronous late
initcall for the full service lifetime. Generic `kernel_init()` therefore did
not reach its normal `free_initmem()` step or transition to `SYSTEM_RUNNING`
while the service was active.

PR #127 separates one-time control initialization from the long-running runtime.
The control late initcall creates its IRQ/event/kthread state and returns. Linux
then executes normal finalization, including `free_initmem()`, the transition to
`SYSTEM_RUNNING`, and `rcu_end_inkernel_boot()`. Only after those steps does the
architecture's post-kernel-init hook publish the control-ready marker and enter
the long-lived service wait/cleanup path.

TCPCC cannot use generic `free_initmem_default()`: the `vmlinux` executable is a
host ELF mapping, while `virt_to_page()` deliberately addresses only the
separate `tcpcc_physmem` guest-RAM arena. The architecture therefore overrides
`free_initmem()` and `munmap()`s the page-aligned `__init_begin` to `__init_end`
range through the host boundary. Removing the mapping also turns an accidental
post-init reference into an immediate fault rather than permitting file-backed
init code to be faulted in again.

The current Linux 6.18.51 image reports a 96 KiB init range and runtime logs
confirm that it is unmapped before the control-ready marker. Ready PSS fell by
about 104 KiB in the validating run, consistent with reclaiming that host ELF
mapping. M10 capacity/reclaim behavior and M11 active CPU remained within the
normal baseline range.

The linker currently places `PERCPU_SECTION` inside those init bounds. The
resolved production image has a zero-byte `.data..percpu` section; final-link
validation makes that a hard invariant. If a future configuration introduces
runtime per-CPU storage, the linker layout must move that storage outside the
discarded range before the build is accepted.

See [`runtime-lifecycle.md`](runtime-lifecycle.md) for the complete boot,
signal, child-process, and shutdown ordering.

## Where to look next

The current low-risk static pruning pass is intentionally considered complete.
Further work should be evidence-driven rather than continuing to remove tiny
symbols or generic networking facilities.

The most plausible remaining MiB-scale question is whether real low-memory
OpenVZ runs retain significant host RSS because guest free memory is fragmented
into order-0/order-1 blocks below the current page-reporting minimum order of 2.
That should first be measured with buddy-order telemetry. Only if the data shows
a meaningful stranded free-page population should lower-order reporting or a
batched alternative be evaluated.

Other ideas such as larger guest base pages, removing IPv6, or patching generic
Linux networking can save memory or text, but each changes a substantially
larger architectural or maintenance boundary. They are not current default
follow-up work without deployment evidence.

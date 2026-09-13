# TCPCC memory-footprint measurement

Memory-footprint work must distinguish static linked-image size, guest-visible
memory ownership, and outer-host physical charging. A reduction in one layer is
not evidence that the others fell by the same amount.

The CI baseline intentionally makes no production configuration change. It
records the fully resolved `ARCH=tcpcc` configuration and the linked `vmlinux`
footprint so later pruning changes can be compared against stable artifacts.

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

### Rejected SLUB_TINY experiment

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
loopback TCP startup stress test. They account for 192 KiB of process-lifetime
`.bss` even though their contents are dead once the selftest passes.

At the time this optimization was introduced, simply annotating those arrays
`__initdata` would not have reclaimed them: the production control runtime
blocked inside a synchronous late initcall until shutdown, so generic
`kernel_init()` never reached its normal `free_initmem()` step during service
life. In addition, the executable image is a host mapping separate from TCPCC's
guest buddy-managed RAM.

The supported optimization is therefore to allocate each 64 KiB selftest buffer
as an order-4 guest page allocation immediately before M4.1, then return all
three allocations to the guest allocator when the test completes. The existing
page-reporting path accepts order >= 2 frees, so these temporary order-4 ranges
can subsequently be discarded from host backing while the production runtime
continues. The M4.1 stress workload itself remains 16 rounds of 64 KiB in each
direction.

The link validation also places a 192 KiB ceiling on permanent `.bss`. This is a
drift guard against reintroducing large temporary diagnostics as process-lifetime
static state; it is not a claim that `.bss` size alone equals runtime RSS.

## Reclaim the hosted init image

The hosted lifecycle now allows generic `kernel_init()` to finish instead of
keeping the kernel in a synchronous late initcall for the full service lifetime.
The control late initcall creates its IRQ/event/kthread state and returns. Linux
can then execute its ordinary finalization sequence, including `free_initmem()`,
transition to `SYSTEM_RUNNING`, and `rcu_end_inkernel_boot()`. Only after those
steps does the architecture's post-kernel-init hook publish the existing control
ready marker and own the long-running service wait/cleanup path.

TCPCC cannot use generic `free_initmem_default()`: the `vmlinux` executable is a
host ELF mapping, while `virt_to_page()` deliberately addresses only the
separate `tcpcc_physmem` guest-RAM arena. The architecture therefore overrides
`free_initmem()` and `munmap()`s the page-aligned `__init_begin` to `__init_end`
range through the host boundary. Unlike `MADV_DONTNEED` on a file-backed ELF
mapping, removing the mapping also turns an accidental post-init reference into
an immediate fault rather than allowing discarded code to be faulted back in.

The linker currently places `PERCPU_SECTION` inside those init bounds. The
resolved production image has a zero-byte `.data..percpu` section; final-link
validation makes that a hard invariant. If a future configuration introduces
runtime per-CPU storage, the linker layout must move that storage outside the
discarded range before the build is accepted.

This lifecycle change is not expected to reduce static ELF file size. Its
runtime saving is the resident host mapping occupied by the aligned init image
(about 96 KiB on the pre-change Linux 6.18.51 baseline), with no intended
TCP/BBR/fq or packet-processing hot-path change.
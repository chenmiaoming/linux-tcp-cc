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

## First allocator-footprint experiment: SLUB_TINY

The first production Kconfig experiment after the baseline enables upstream
`CONFIG_SLUB_TINY`. TCPCC is permanently single-vCPU (`NR_CPUS=1`), so retaining
empty or partial slabs for allocator scalability is a poor fit for the product.
Upstream's tiny SLUB mode sets the retained partial-slab targets to zero and
trades allocator scalability/debug facilities for lower memory retention.

This experiment deliberately does **not** enable `CC_OPTIMIZE_FOR_SIZE` and does
not change TCP, BBR, fq, page reporting, or the tcpcc data path. Keeping those
changes separate makes static and runtime deltas attributable to the allocator
policy alone.

The pre-change Linux 6.18.51 baseline from PR #122 is:

- `vmlinux`: 2,755,880 bytes;
- GNU allocated size: 2,639,257 bytes;
- GNU text/data/bss: 2,004,968 / 310,800 / 323,489 bytes; and
- 116 resolved `CONFIG_*=y/m` symbols.

`SLUB_TINY` itself is an additional enabled control symbol, so a higher enabled
symbol count is not by itself a footprint regression. Qualification must compare
actual linked bytes and hosted memory telemetry. A real deployment claim still
requires measuring guest free/available/slab memory and outer OpenVZ
`physpages`; CI static-size changes cannot establish host backing-page savings.

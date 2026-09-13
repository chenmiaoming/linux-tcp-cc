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

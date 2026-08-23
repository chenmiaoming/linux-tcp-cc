# Linux 6.18 userspace architecture port: M2 plan

M2 is split into reviewable steps. The product branch must never carry a large,
unreviewable userspace-kernel port as one change.

## M2.1 — Kbuild/Kconfig architecture skeleton

Goal: make `ARCH=tcpcc` a first-class Linux 6.18 build target with the smallest
possible architecture contract and aggressive use of `asm-generic`.

Exit criteria:

- project-owned architecture sources live under `linux-overlay/arch/tcpcc/`;
- `make ARCH=tcpcc defconfig` succeeds against the pinned Linux 6.18.y tree;
- `make ARCH=tcpcc prepare` succeeds;
- the architecture is single-CPU, 64-bit, little-endian, no-MMU for the first
  bring-up iteration;
- no TCP/congestion-control source is modified.

`linux-overlay/` is append-only relative to pristine upstream Linux. Any change
to a path that already exists upstream must be an explicit patch in
`patches/series`; `prepare-linux.sh` rejects overlay collisions.

## M2.2 — Link and early kernel substrate

Goal: add the architecture-specific entry, linker layout, task/thread substrate,
early memory and IRQ stubs required to link a userspace-hosted kernel object.

Exit criteria:

- the kernel links deterministically for `ARCH=tcpcc`;
- unresolved architecture symbols are eliminated rather than hidden;
- host-runtime behavior is still stubbed where M3 owns the implementation;
- no TCP/congestion-control source is modified.

## M2.3 — Bootstrap into start_kernel

Goal: provide only the host bootstrap, console and panic path needed to execute
the linked kernel far enough to prove architecture bring-up.

Exit criteria:

- a normal POSIX executable enters Linux `start_kernel()`;
- printk reaches the host console;
- a deterministic boot milestone is observed before subsystems owned by M3;
- panic exits deterministically with diagnostic output.

## Reference policy

`arch/tcpcc` is a new Linux 6.18 port. LKL is an implementation reference for a
small host boundary, not a dependency or source base. Linux 6.18 User-Mode Linux
(`arch/um`) is the primary reference for current Kbuild and host-build behavior.
All copied or adapted code must retain appropriate SPDX/copyright attribution.

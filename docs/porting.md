# Linux version portability

TCPCC has a deliberately small textual conflict surface and a larger semantic
dependency surface. Treat those separately when moving to another Linux
series.

## Modification surface

The production Linux tree is reconstructed from three inputs:

1. the exact upstream tag in `upstream/linux.env`;
2. explicit patches listed by `patches/series`; and
3. the append-only `linux-overlay/arch/tcpcc` architecture.

The overlay must never replace an upstream path. At the current baseline there
are two deliberate generic-kernel patches:

- an IPv6 device-address helper in `include/net/addrconf.h` and
  `net/ipv6/addrconf.c`; and
- a narrow default-no-op `arch_post_kernel_init()` hook in `init/main.c`, used
  by `ARCH=tcpcc` only after generic boot finalization has completed.

The second patch is intentionally placed after `free_initmem()`, the transition
to `SYSTEM_RUNNING`, and `rcu_end_inkernel_boot()`. It lets the hosted
architecture enter its long-lived control runtime without keeping a synchronous
late initcall alive for the whole service lifetime. BBR, TCP rate sampling,
recovery, and fq remain protected upstream sources rather than project forks.

## Compatibility boundary

`arch/tcpcc/kernel/compat.c` owns direct use of unstable networking internals:

- IPv4 `devinet_ioctl` address and netmask configuration;
- IPv4 FIB table creation and route insertion;
- the patched IPv6 address helper;
- IPv6 route insertion;
- the `init_net.ipv4.sysctl_tcp_wmem` autotuning ceiling; and
- root-qdisc inspection under RTNL.

`l3net.c` calls only the project-level operations declared by
`asm/tcpcc_compat.h`. When an upstream signature, structure member, or locking
contract changes, adapt `compat.c` first and keep the L3 data plane and control
ABI unchanged. `scripts/check-portability-boundary.sh` prevents the contained
API calls from spreading back into architecture consumers.

`arch/tcpcc/kernel/compat_mm.c` similarly owns the page allocator bootstrap and
shared zero-page transition. Linux before 7.3 calls `free_area_init()` from the
architecture and supplies its zero page there; Linux 7.3 calls the allocator
from generic initialization and asks the architecture only for zone limits.
`arch/tcpcc/kernel/compat_time.c` owns the high-resolution timer readiness
probe; the port relies on the public timer resolution rather than the
`hrtimer_is_hres_active()` helper removed in Linux 7.3.
`arch/tcpcc/kernel/compat_socket.c` owns kernel bind/connect address typing;
Linux 7.3 changed those two helpers from `sockaddr` to `sockaddr_unsized`, while
the control and data-plane callers continue to pass their concrete IPv4 or IPv6
address structures through a stable project interface.

The hosted init-image ownership is a separate portability concern from guest
page allocation. `arch/tcpcc/kernel/initmem.c` overrides `free_initmem()` because
the executable's `__init` range is a host ELF mapping rather than part of the
`tcpcc_physmem` guest arena. `host_mman.c` removes that page-aligned range with
host `munmap(2)`. The linker currently places `PERCPU_SECTION` inside those init
bounds, so final-link validation requires `.data..percpu == 0` until the linker
layout is changed.

The remaining high-risk internal dependencies are intentionally recorded for
future compatibility-layer work:

| Area | Current dependency | Primary files |
| --- | --- | --- |
| Scheduling | `copy_thread`, `schedule_tail`, task stack/context ownership | `process.c`, `switch.S` |
| Interrupt entry | IRQ chip setup, `irq_enter`/`irq_exit`, IRQ register frame | `irq.c`, `time.c` |
| Time | clocksource, clockevent and hrtimer initialization | `time.c` |
| Memory | memblock, `free_area_init`, NOMMU page model | `setup.c`, `page.h`, `compat_mm.c` |
| Init lifecycle | generic `kernel_init()` finalization point and architecture post-init hook | `init/main.c`, `control.c`, `initmem.c` |
| Reclaim | page-reporting registration and scatterlist batches | `reclaim.c` |
| Sockets | kernel socket creation and `sk_*` callbacks | `bridge.c`, `service.c`, `control.c` |
| L3 data plane | netdevice/SKB transmit and receive contracts | `l3net.c` |
| Link | generic linker-script macros, init bounds, and zero-sized runtime percpu invariant | `vmlinux.lds.S`, `scripts/validate-tcpcc-link.sh` |

## Mainline canary

`.github/workflows/next-kernel-canary.yml` runs every Monday and whenever the
portability surface changes in a pull request. It fetches the current `master`
commit from Linus Torvalds' kernel.org repository, applies the exact project
patch series and overlay, resolves the TCPCC defconfig, and requests a complete
`ARCH=tcpcc vmlinux` link. It does not publish a package and does not change the
6.18.y release pin.

The canary is expected to fail when upstream changes an internal contract. Its
artifact records the exact mainline commit, version, config, and verbose build
log. Triage failures in this order:

1. generic patch application and overlay path collisions;
2. Kconfig and architecture header contracts;
3. compatibility-boundary APIs;
4. scheduler, IRQ, time, memory, init-lifecycle and linker contracts; then
5. full runtime suites after selecting the next supported LTS tag.

A green canary proves compile/link compatibility only. Release eligibility
still requires the pinned, signed LTS tag and the complete hosted runtime CI.

The first canary against Linux 7.3-rc1 found the generic page-size and zero-page
transition, allocator bootstrap ownership, high-resolution timer probe removal,
and kernel bind/connect address-type change. The corresponding architecture
contracts now live behind narrow compatibility units rather than version checks
spread through the data plane.

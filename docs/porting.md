# Linux version portability

TCPCC has a deliberately small textual conflict surface and a larger semantic
dependency surface. Treat those separately when moving to another Linux
series.

## Modification surface

The production Linux tree is reconstructed from three inputs:

1. the exact upstream tag in `upstream/linux.env`;
2. explicit patches listed by `patches/series`; and
3. the append-only `linux-overlay/arch/tcpcc` architecture.

The overlay must never replace an upstream path. At the current baseline the
only generic-kernel patch exposes an IPv6 device-address helper in
`include/net/addrconf.h` and `net/ipv6/addrconf.c`. BBR, TCP rate sampling,
recovery, and fq remain protected upstream sources rather than project forks.

## Compatibility boundary

`arch/tcpcc/kernel/compat.c` owns direct use of unstable networking internals:

- IPv4 `devinet_ioctl` address and netmask configuration;
- IPv4 FIB table creation and route insertion;
- the patched IPv6 address helper;
- IPv6 route insertion; and
- root-qdisc inspection under RTNL.

`l3net.c` calls only the project-level operations declared by
`asm/tcpcc_compat.h`. When an upstream signature, structure member, or locking
contract changes, adapt `compat.c` first and keep the L3 data plane and control
ABI unchanged. `scripts/check-portability-boundary.sh` prevents the contained
API calls from spreading back into architecture consumers.

The remaining high-risk internal dependencies are intentionally recorded for
future compatibility-layer work:

| Area | Current dependency | Primary files |
| --- | --- | --- |
| Scheduling | `copy_thread`, `schedule_tail`, task stack/context ownership | `process.c`, `switch.S` |
| Interrupt entry | IRQ chip setup, `irq_enter`/`irq_exit`, IRQ register frame | `irq.c`, `time.c` |
| Time | clocksource, clockevent and hrtimer initialization | `time.c` |
| Memory | memblock, `free_area_init`, NOMMU page model | `setup.c`, `page.h` |
| Reclaim | page-reporting registration and scatterlist batches | `reclaim.c` |
| Sockets | kernel socket creation and `sk_*` callbacks | `bridge.c`, `service.c`, `control.c` |
| L3 data plane | netdevice/SKB transmit and receive contracts | `l3net.c` |
| Link | generic linker-script macros and init sections | `vmlinux.lds.S` |

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
4. scheduler, IRQ, time, memory and linker contracts; then
5. full runtime suites after selecting the next supported LTS tag.

A green canary proves compile/link compatibility only. Release eligibility
still requires the pinned, signed LTS tag and the complete hosted runtime CI.

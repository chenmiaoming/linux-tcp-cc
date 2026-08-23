/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_HOST_H
#define _ASM_TCPCC_HOST_H

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/types.h>

/*
 * tcpcc host boundary.
 *
 * The architecture is currently tied to an x86-64 Linux host process. Keep
 * these primitives private to arch/tcpcc: Linux core/TCP code must observe
 * normal kernel memory, time and scheduling semantics rather than host APIs.
 */
void tcpcc_host_write(const char *buf, size_t len);
void __noreturn tcpcc_host_exit(int status);
void *__init tcpcc_host_map_anon(size_t len);

/*
 * M3.2 host time/event primitives. The timer fd is only a wakeup source: host
 * execution must never enter Linux asynchronously. The single Linux vCPU
 * explicitly waits for an expiration and dispatches it from a safe point.
 */
u64 tcpcc_host_monotonic_ns(void);
int __init tcpcc_host_timer_create(void);
int tcpcc_host_timer_arm(int fd, u64 delta_ns);
int tcpcc_host_timer_cancel(int fd);
int tcpcc_host_timer_wait(int fd, u64 *expirations);

/*
 * M3.3 idle bridge. The Linux idle task enters this with local IRQs masked;
 * the implementation atomically crosses to the synchronous host timer wait
 * model by enabling local IRQs and dispatching the pending clockevent on wake.
 * General multi-fd host event multiplexing remains outside this milestone.
 */
void tcpcc_host_idle_wait(void);

void __init tcpcc_host_console_init(void);
void __init tcpcc_host_install_panic_exit(void);

#endif /* _ASM_TCPCC_HOST_H */

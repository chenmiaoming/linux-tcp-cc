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
 * normal kernel memory, time, IRQ and scheduling semantics rather than host
 * APIs.
 */
#define TCPCC_HOST_STDIN_FILENO  0
#define TCPCC_HOST_STDOUT_FILENO 1

void tcpcc_host_write(const char *buf, size_t len);
ssize_t tcpcc_host_read_fd(int fd, void *buf, size_t len);
ssize_t tcpcc_host_write_fd(int fd, const void *buf, size_t len);
void __noreturn tcpcc_host_exit(int status);
void *__init tcpcc_host_map_anon(size_t len);
int tcpcc_host_close(int fd);
int tcpcc_host_set_nonblock(int fd);

u64 tcpcc_host_monotonic_ns(void);
int __init tcpcc_host_timer_create(void);
int tcpcc_host_timer_arm(int fd, u64 delta_ns);
int tcpcc_host_timer_cancel(int fd);
int tcpcc_host_timer_wait(int fd, u64 *expirations);

/*
 * M3.4 host event multiplexer. Host readiness is asynchronous, but Linux is
 * never entered asynchronously: the single vCPU calls event_wait() only from
 * an IRQ-enabled safe point and dispatches returned events serially.
 */
#define TCPCC_HOST_EVENT_TIMER    1ULL
#define TCPCC_HOST_EVENT_IRQ_BASE 0x100ULL

int __init tcpcc_host_event_loop_init(void);
int tcpcc_host_event_add(int fd, u64 token);
int tcpcc_host_event_del(int fd);
int tcpcc_host_event_wait(u64 *token);

/*
 * Linux idle entry point. M3.4 waits on the host event multiplexer and routes
 * the returned source through the normal clockevent or generic IRQ path.
 */
void tcpcc_host_idle_wait(void);

void __init tcpcc_host_console_init(void);
void __init tcpcc_host_install_panic_exit(void);

#endif /* _ASM_TCPCC_HOST_H */

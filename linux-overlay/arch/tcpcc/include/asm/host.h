/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_HOST_H
#define _ASM_TCPCC_HOST_H

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/types.h>

/*
 * M2.3 host boundary.
 *
 * The initial tcpcc architecture is intentionally tied to an x86-64 Linux
 * host process.  These primitives are architecture-private and must not leak
 * into upstream TCP/CC code.  M3 will grow this into the explicit host runtime
 * interface for clocks, wakeups, memory and packet I/O.
 */
void tcpcc_host_write(const char *buf, size_t len);
void __noreturn tcpcc_host_exit(int status);

void __init tcpcc_host_console_init(void);
void __init tcpcc_host_install_panic_exit(void);

#endif /* _ASM_TCPCC_HOST_H */

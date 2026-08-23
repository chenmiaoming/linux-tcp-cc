/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_HOST_H
#define _ASM_TCPCC_HOST_H

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/types.h>

/*
 * Hosted runtime boundary.
 *
 * The initial tcpcc architecture is intentionally tied to an x86-64 Linux
 * host process. These primitives are architecture-private and must not leak
 * into upstream TCP/CC code. M3 grows this boundary only when a Linux core
 * subsystem needs a real host primitive.
 */
void tcpcc_host_write(const char *buf, size_t len);
void __noreturn tcpcc_host_exit(int status);

/*
 * Map [start, end) as anonymous read/write host memory at the exact requested
 * virtual addresses. The current NOMMU architecture uses identity __pa/__va,
 * so setup_arch() deliberately keeps this arena in the low fixed-address
 * physical window established by the linker contract.
 */
long __init tcpcc_host_map_memory(unsigned long start, unsigned long end);

void __init tcpcc_host_console_init(void);
void __init tcpcc_host_install_panic_exit(void);

#endif /* _ASM_TCPCC_HOST_H */

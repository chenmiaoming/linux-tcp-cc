/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_HOST_H
#define _ASM_TCPCC_HOST_H

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/types.h>

/*
 * tcpcc host boundary.
 *
 * The architecture is currently tied to an x86-64 Linux host process.  Keep
 * these primitives private to arch/tcpcc: Linux core/TCP code must observe
 * normal kernel memory, time and scheduling semantics rather than host APIs.
 */
void tcpcc_host_write(const char *buf, size_t len);
void __noreturn tcpcc_host_exit(int status);
void *__init tcpcc_host_map_anon(size_t len);

void __init tcpcc_host_console_init(void);
void __init tcpcc_host_install_panic_exit(void);

#endif /* _ASM_TCPCC_HOST_H */

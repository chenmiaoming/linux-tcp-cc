/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_VMALLOC_H
#define _ASM_TCPCC_VMALLOC_H

/*
 * tcpcc starts as a NOMMU architecture. There are no architecture-specific
 * vmalloc address-space hooks at this stage; the generic !CONFIG_MMU paths in
 * include/linux/vmalloc.h provide the required behavior. This intentionally
 * mirrors Linux 6.18 NOMMU architectures such as m68k, whose asm/vmalloc.h is
 * empty.
 */

#endif /* _ASM_TCPCC_VMALLOC_H */

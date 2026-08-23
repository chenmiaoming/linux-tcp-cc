/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_MMU_CONTEXT_H
#define _ASM_TCPCC_MMU_CONTEXT_H

/*
 * tcpcc is NOMMU during the initial hosted bring-up. Linux 6.18 provides the
 * exact generic contract for architectures with no address-space switch: the
 * switch_mm() hook is a no-op and the remaining common hooks are inherited
 * from asm-generic/mmu_context.h.
 */
#include <asm-generic/nommu_context.h>

#endif /* _ASM_TCPCC_MMU_CONTEXT_H */

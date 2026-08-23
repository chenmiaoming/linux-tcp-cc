/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_CURRENT_H
#define _ASM_TCPCC_CURRENT_H

#include <linux/compiler.h>

#ifndef __ASSEMBLY__
struct task_struct;

/*
 * The hosted runtime owns the current-task pointer. M2 establishes this ABI;
 * the bootstrap/scheduler runtime will provide the storage and switch it when
 * execution moves between Linux tasks.
 */
extern struct task_struct *tcpcc_current_task;

static __always_inline struct task_struct *get_current(void)
{
	return READ_ONCE(tcpcc_current_task);
}

#define current get_current()
#endif

#endif /* _ASM_TCPCC_CURRENT_H */

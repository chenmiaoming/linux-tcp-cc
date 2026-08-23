/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_THREAD_INFO_H
#define _ASM_TCPCC_THREAD_INFO_H

#define THREAD_SIZE 4096

#ifndef __ASSEMBLY__
#include <linux/types.h>

struct task_struct;
struct thread_info {
	unsigned long flags;
};

#define INIT_THREAD_INFO(tsk) { .flags = 0 }

extern struct thread_info *current_thread_info(void);
unsigned long *arch_alloc_thread_stack_node(struct task_struct *tsk, int node);
void arch_free_thread_stack(struct task_struct *tsk);

#define TIF_SIGPENDING 0
#define TIF_NEED_RESCHED 1
#define TIF_NOTIFY_SIGNAL 2
#define TIF_NOTIFY_RESUME 3
#define TIF_MEMDIE 4
#endif

#endif

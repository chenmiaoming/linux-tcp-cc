/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_THREAD_INFO_H
#define _ASM_TCPCC_THREAD_INFO_H

#define THREAD_SIZE 4096

#ifndef __ASSEMBLY__
#include <linux/types.h>

struct task_struct;

/*
 * CONFIG_THREAD_INFO_IN_TASK keeps this structure at offset zero in
 * task_struct. The architecture owns `current`; generic thread-info code then
 * derives current_thread_info() by casting current.
 */
struct thread_info {
	unsigned long flags;
	__u32 cpu;
	int preempt_count;
};

#define INIT_THREAD_INFO(tsk)                    \
{                                                \
	.flags = 0,                                  \
	.cpu = 0,                                    \
	.preempt_count = INIT_PREEMPT_COUNT,         \
}

unsigned long *arch_alloc_thread_stack_node(struct task_struct *tsk, int node);
void arch_free_thread_stack(struct task_struct *tsk);
#endif /* !__ASSEMBLY__ */

/* Low-level work flags. Keep reschedule and signal bits explicit because the
 * generic scheduler tests their mask forms directly. */
#define TIF_SIGPENDING      0
#define TIF_NEED_RESCHED    1
#define TIF_NOTIFY_SIGNAL   2
#define TIF_NOTIFY_RESUME   3
#define TIF_MEMDIE          4

#define _TIF_SIGPENDING     (1UL << TIF_SIGPENDING)
#define _TIF_NEED_RESCHED   (1UL << TIF_NEED_RESCHED)
#define _TIF_NOTIFY_SIGNAL  (1UL << TIF_NOTIFY_SIGNAL)
#define _TIF_NOTIFY_RESUME  (1UL << TIF_NOTIFY_RESUME)
#define _TIF_MEMDIE         (1UL << TIF_MEMDIE)

#define _TIF_WORK_MASK (_TIF_SIGPENDING | _TIF_NEED_RESCHED | \
                        _TIF_NOTIFY_SIGNAL | _TIF_NOTIFY_RESUME)

#endif /* _ASM_TCPCC_THREAD_INFO_H */

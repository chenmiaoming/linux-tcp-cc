/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_THREAD_INFO_H
#define _ASM_TCPCC_THREAD_INFO_H

/*
 * Hosted kernel threads execute ordinary Linux scheduler/kthread call chains.
 * Use a 16 KiB stack, matching the practical x86-64 kernel-stack scale rather
 * than the 4 KiB M2 link/bootstrap placeholder.
 */
#define THREAD_SIZE_ORDER 2
#define THREAD_SIZE 16384

#ifndef __ASSEMBLY__
#include <linux/types.h>

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
#endif /* !__ASSEMBLY__ */

/*
 * Generic Linux code names several syscall-work bits even when a particular
 * architecture does not implement a userspace syscall entry path. Keep the
 * numbering aligned with Linux 6.18 UML so task/fork bookkeeping compiles
 * without implying any guest userspace ABI for tcpcc.
 */
#define TIF_SYSCALL_TRACE          0
#define TIF_SIGPENDING             1
#define TIF_NEED_RESCHED           2
#define TIF_NOTIFY_SIGNAL          3
#define TIF_RESTART_BLOCK          4
#define TIF_MEMDIE                 5
#define TIF_SYSCALL_AUDIT          6
#define TIF_RESTORE_SIGMASK        7
#define TIF_NOTIFY_RESUME          8
#define TIF_SECCOMP                9
#define TIF_SINGLESTEP            10
#define TIF_SYSCALL_TRACEPOINT    11

#define _TIF_SYSCALL_TRACE        (1UL << TIF_SYSCALL_TRACE)
#define _TIF_SIGPENDING           (1UL << TIF_SIGPENDING)
#define _TIF_NEED_RESCHED         (1UL << TIF_NEED_RESCHED)
#define _TIF_NOTIFY_SIGNAL        (1UL << TIF_NOTIFY_SIGNAL)
#define _TIF_RESTART_BLOCK        (1UL << TIF_RESTART_BLOCK)
#define _TIF_MEMDIE               (1UL << TIF_MEMDIE)
#define _TIF_SYSCALL_AUDIT        (1UL << TIF_SYSCALL_AUDIT)
#define _TIF_RESTORE_SIGMASK      (1UL << TIF_RESTORE_SIGMASK)
#define _TIF_NOTIFY_RESUME        (1UL << TIF_NOTIFY_RESUME)
#define _TIF_SECCOMP              (1UL << TIF_SECCOMP)
#define _TIF_SINGLESTEP           (1UL << TIF_SINGLESTEP)
#define _TIF_SYSCALL_TRACEPOINT   (1UL << TIF_SYSCALL_TRACEPOINT)

#define _TIF_WORK_MASK (_TIF_NEED_RESCHED | _TIF_SIGPENDING | \
                        _TIF_NOTIFY_SIGNAL | _TIF_NOTIFY_RESUME)

#endif /* _ASM_TCPCC_THREAD_INFO_H */

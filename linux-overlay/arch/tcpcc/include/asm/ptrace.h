/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_PTRACE_H
#define _ASM_TCPCC_PTRACE_H

#include <linux/errno.h>

struct task_struct;

/*
 * tcpcc executes Linux networking code in kernel context only. There is no
 * guest userspace privilege level in the initial architecture, so pt_regs is
 * an internal execution-frame placeholder. The zero-valued PC/SP helpers are
 * deliberate M2 link-time sentinels: generic syscall/signal/ptrace code is
 * built by Linux, but no tcpcc execution path may treat these as a real guest
 * register ABI.
 *
 * The host bootstrap/context-switch implementation may extend this structure
 * without creating a UAPI commitment.
 */
struct pt_regs {
	unsigned long reserved;
};

#define user_mode(regs)              (0)
#define kernel_mode(regs)            (1)
#define profile_pc(regs)             (0UL)
#define instruction_pointer(regs)    (0UL)
#define user_stack_pointer(regs)     (0UL)

/* tcpcc has no guest ptrace ABI in M2. */
static inline long arch_ptrace(struct task_struct *child, long request,
			       unsigned long addr, unsigned long data)
{
	return -EINVAL;
}

static inline void ptrace_disable(struct task_struct *child)
{
}

#endif /* _ASM_TCPCC_PTRACE_H */

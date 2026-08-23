/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_PROCESSOR_H
#define _ASM_TCPCC_PROCESSOR_H

#include <linux/compiler.h>

struct task_struct;
struct pt_regs;

/*
 * A hosted task keeps its inactive x86-64 SysV context on the Linux kernel
 * stack itself.  switch.S saves the six callee-saved registers and stores the
 * resulting stack pointer here.  The remaining fields describe the synthetic
 * first frame created by copy_thread() for kernel threads.
 */
struct thread_struct {
	unsigned long sp;
	struct task_struct *prev_sched;
	int (*fn)(void *);
	void *fn_arg;
};

#define INIT_THREAD { \
	.sp = 0, \
	.prev_sched = NULL, \
	.fn = NULL, \
	.fn_arg = NULL, \
}

#define TASK_SIZE (~0UL)
#define TASK_UNMAPPED_BASE 0UL
#define KSTK_EIP(tsk) 0UL
#define KSTK_ESP(tsk) 0UL

static inline void cpu_relax(void) { barrier(); }
static inline unsigned long thread_saved_pc(struct task_struct *tsk) { return 0; }
static inline unsigned long __get_wchan(struct task_struct *p) { return 0; }
static inline void flush_thread(void) { }
#define task_pt_regs(tsk) ((struct pt_regs *)0)

#endif

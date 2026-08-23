/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_PROCESSOR_H
#define _ASM_TCPCC_PROCESSOR_H

#include <linux/compiler.h>

struct task_struct;
struct pt_regs;

struct thread_struct { };
#define INIT_THREAD { }
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

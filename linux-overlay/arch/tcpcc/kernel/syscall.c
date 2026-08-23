// SPDX-License-Identifier: GPL-2.0-only
#include <linux/sched.h>
#include <asm/syscall.h>

int syscall_get_arch(struct task_struct *task)
{
	/* M2 exposes no guest userspace syscall ABI. */
	return 0;
}

// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/switch_to.h>

/* Linux boots in init_task; M3 will update this at hosted context switches. */
struct task_struct *tcpcc_current_task = &init_task;

int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
{
	/* Host execution-context construction belongs to M3. */
	return -EOPNOTSUPP;
}

struct task_struct *__switch_to(struct task_struct *prev,
				       struct task_struct *next)
{
	/*
	 * Returning without switching the host stack would silently corrupt Linux
	 * scheduler semantics.  Keep this an explicit M3 execution sentinel.
	 */
	panic("tcpcc: task context switching requires the M3 host runtime");
}

static void __noreturn tcpcc_m2_stop(void)
{
	/* M3 replaces this with the host process lifecycle boundary. */
	for (;;)
		cpu_relax();
}

void machine_restart(char *cmd)
{
	tcpcc_m2_stop();
}

void machine_halt(void)
{
	tcpcc_m2_stop();
}

void machine_power_off(void)
{
	tcpcc_m2_stop();
}

void show_regs(struct pt_regs *regs)
{
	/* No guest register ABI exists in M2. */
}

void show_stack(struct task_struct *task, unsigned long *sp,
		const char *loglvl)
{
	/* Host stack unwinding belongs to M3. */
}

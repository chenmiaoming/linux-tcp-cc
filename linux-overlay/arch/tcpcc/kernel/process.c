// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/panic.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <asm/current.h>
#include <asm/host.h>
#include <asm/processor.h>
#include <asm/switch_to.h>

#define TCPCC_TASK_TEST_WORKERS 4
#define TCPCC_TASK_TEST_ROUNDS  32
#define TCPCC_TASK_TEST_RC_BASE 0x30

/* Linux boots in init_task; every hosted context switch updates this pointer. */
struct task_struct *tcpcc_current_task = &init_task;

extern void tcpcc_switch_context(unsigned long *prev_sp,
				 unsigned long next_sp);

static void __noreturn tcpcc_kernel_thread_entry(void)
{
	struct task_struct *prev = current->thread.prev_sched;
	int (*fn)(void *) = current->thread.fn;
	void *arg = current->thread.fn_arg;
	int ret;

	if (!prev)
		panic("tcpcc: first task entry has no previous scheduler task");
	if (!fn)
		panic("tcpcc: first task entry has no kernel-thread function");

	/* This first-frame ownership is consumed exactly once. */
	current->thread.prev_sched = NULL;
	schedule_tail(prev);

	ret = fn(arg);
	do_exit(ret);
}

static void tcpcc_prepare_kernel_stack(struct task_struct *p)
{
	unsigned long top = (unsigned long)task_stack_page(p) + THREAD_SIZE;
	unsigned long *sp = (unsigned long *)(top & ~0xfUL);
	unsigned int i;

	/*
	 * tcpcc_switch_context() restores r15,r14,r13,r12,rbp,rbx and returns.
	 * Build that exact inactive frame. The final zero is a poison return
	 * address for tcpcc_kernel_thread_entry(), which is __noreturn. Keeping
	 * it above the entry address also leaves %rsp == 8 (mod 16) at function
	 * entry, as required by the x86-64 SysV ABI.
	 */
	*--sp = 0;
	*--sp = (unsigned long)tcpcc_kernel_thread_entry;
	for (i = 0; i < 6; i++)
		*--sp = 0;

	p->thread.sp = (unsigned long)sp;
}

int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
{
	/*
	 * tcpcc deliberately has no guest userspace register/return ABI yet.
	 * M3.3 needs the kernel-function clone path used by kernel_init,
	 * kthreadd and ordinary kthreads; reject a userspace-style fork instead
	 * of manufacturing register semantics that do not exist.
	 */
	if (!args->fn)
		return -EOPNOTSUPP;

	p->thread = (struct thread_struct)INIT_THREAD;
	p->thread.fn = args->fn;
	p->thread.fn_arg = args->fn_arg;
	tcpcc_prepare_kernel_stack(p);

	return 0;
}

struct task_struct *__switch_to(struct task_struct *prev,
				       struct task_struct *next)
{
	struct task_struct *last;

	if (READ_ONCE(tcpcc_current_task) != prev)
		panic("tcpcc: current ownership mismatch before task switch");
	if (!next->thread.sp)
		panic("tcpcc: scheduler selected task without a hosted context");

	/*
	 * Mirror the scheduler contract used by hosted UML: publish the next
	 * current owner before changing the host stack, and leave the previous
	 * task in the next task's first/resume metadata so the resumed C frame
	 * can return the scheduler's `last` task correctly.
	 */
	next->thread.prev_sched = prev;
	WRITE_ONCE(tcpcc_current_task, next);
	tcpcc_switch_context(&prev->thread.sp, next->thread.sp);

	/* Execution resumes here only when this task is scheduled again. */
	if (READ_ONCE(tcpcc_current_task) != prev)
		panic("tcpcc: current ownership mismatch after task switch");

	last = current->thread.prev_sched;
	if (!last)
		panic("tcpcc: resumed task lost previous scheduler ownership");

	return last;
}

void arch_cpu_idle(void)
{
	/* timerfd is M3.3's only host wakeup source; #27 adds general host IRQs. */
	tcpcc_host_idle_wait();
}

struct tcpcc_task_test_slot {
	struct completion started;
	struct completion rounds_done;
	struct task_struct *task;
	struct task_struct *owner;
	unsigned int id;
	unsigned int rounds;
};

static struct tcpcc_task_test_slot tcpcc_task_test[TCPCC_TASK_TEST_WORKERS];

static int tcpcc_task_test_worker(void *arg)
{
	struct tcpcc_task_test_slot *slot = arg;
	unsigned int round;

	slot->owner = current;
	pr_notice("tcpcc: M3.3 worker %u entered\n", slot->id);
	complete(&slot->started);

	for (round = 0; round < TCPCC_TASK_TEST_ROUNDS; round++) {
		if (current != slot->owner)
			panic("tcpcc: worker %u lost current ownership at round %u",
			      slot->id, round);

		WRITE_ONCE(slot->rounds, round + 1);

		/*
		 * Sleeping for one jiffy guarantees a real scheduler switch and,
		 * once all runnable workers are asleep, drives the idle -> timerfd ->
		 * Linux clockevent wakeup path as well.
		 */
		schedule_timeout_uninterruptible(1);

		if ((round + 1) % 8 == 0)
			pr_notice("tcpcc: M3.3 worker %u woke through round %u\n",
				  slot->id, round + 1);
	}

	complete(&slot->rounds_done);
	pr_notice("tcpcc: M3.3 worker %u completed sleep/wake rounds\n",
		  slot->id);

	/* kthread_stop() must wake this task and collect its deterministic rc. */
	while (!kthread_should_stop()) {
		if (current != slot->owner)
			panic("tcpcc: worker %u lost current ownership while stopping",
			      slot->id);
		schedule_timeout_uninterruptible(1);
	}

	pr_notice("tcpcc: M3.3 worker %u observed stop request\n", slot->id);
	return TCPCC_TASK_TEST_RC_BASE + slot->id;
}

static int __init tcpcc_task_switch_selftest(void)
{
	unsigned int i;
	int ret;

	pr_notice("tcpcc: M3.3 scheduler stress starting\n");

	for (i = 0; i < TCPCC_TASK_TEST_WORKERS; i++) {
		struct tcpcc_task_test_slot *slot = &tcpcc_task_test[i];

		init_completion(&slot->started);
		init_completion(&slot->rounds_done);
		slot->task = NULL;
		slot->owner = NULL;
		slot->id = i;
		slot->rounds = 0;

		pr_notice("tcpcc: M3.3 creating worker %u\n", i);
		slot->task = kthread_run(tcpcc_task_test_worker, slot,
					 "tcpcc-m3.3/%u", i);
		if (IS_ERR(slot->task))
			panic("tcpcc: failed to create task-test worker %u: %ld",
			      i, PTR_ERR(slot->task));
		pr_notice("tcpcc: M3.3 created worker %u\n", i);
	}

	for (i = 0; i < TCPCC_TASK_TEST_WORKERS; i++) {
		struct tcpcc_task_test_slot *slot = &tcpcc_task_test[i];

		pr_notice("tcpcc: M3.3 waiting for worker %u first entry\n", i);
		wait_for_completion(&slot->started);
		if (slot->owner != slot->task)
			panic("tcpcc: worker %u current pointer does not match task",
			      i);
	}
	pr_notice("tcpcc: M3.3 all workers entered\n");

	for (i = 0; i < TCPCC_TASK_TEST_WORKERS; i++) {
		struct tcpcc_task_test_slot *slot = &tcpcc_task_test[i];

		pr_notice("tcpcc: M3.3 waiting for worker %u sleep/wake completion\n",
			  i);
		wait_for_completion(&slot->rounds_done);
		if (READ_ONCE(slot->rounds) != TCPCC_TASK_TEST_ROUNDS)
			panic("tcpcc: worker %u completed only %u/%u rounds",
			      i, READ_ONCE(slot->rounds), TCPCC_TASK_TEST_ROUNDS);
	}
	pr_notice("tcpcc: M3.3 all workers completed sleep/wake rounds\n");

	/*
	 * Stop and reap every context before declaring success. kthread_stop()
	 * both wakes a sleeping worker and waits until Linux has completed its
	 * task-exit path, which catches stale/dead-context resume bugs.
	 */
	for (i = 0; i < TCPCC_TASK_TEST_WORKERS; i++) {
		struct tcpcc_task_test_slot *slot = &tcpcc_task_test[i];

		pr_notice("tcpcc: M3.3 stopping worker %u\n", i);
		ret = kthread_stop(slot->task);
		if (ret != TCPCC_TASK_TEST_RC_BASE + i)
			panic("tcpcc: worker %u stop returned %d, expected %u",
			      i, ret, TCPCC_TASK_TEST_RC_BASE + i);
		slot->task = NULL;
		pr_notice("tcpcc: M3.3 reaped worker %u with rc %d\n", i, ret);
	}

	pr_notice("tcpcc: M3.3 task-switch stress passed (%u workers x %u sleep/wake rounds)\n",
		  TCPCC_TASK_TEST_WORKERS, TCPCC_TASK_TEST_ROUNDS);
	panic("tcpcc: M3.3 reached task-switch boundary after scheduler stress");
}
core_initcall(tcpcc_task_switch_selftest);

static void __noreturn tcpcc_m3_stop(void)
{
	for (;;)
		cpu_relax();
}

void machine_restart(char *cmd)
{
	tcpcc_m3_stop();
}

void machine_halt(void)
{
	tcpcc_m3_stop();
}

void machine_power_off(void)
{
	tcpcc_m3_stop();
}

void show_regs(struct pt_regs *regs)
{
	/* No guest register ABI exists yet. */
}

void show_stack(struct task_struct *task, unsigned long *sp,
		const char *loglvl)
{
	/* Hosted stack unwinding is not required for the M3.3 scheduler ABI. */
}

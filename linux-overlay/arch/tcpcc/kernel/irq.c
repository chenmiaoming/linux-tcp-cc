// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/irqflags.h>
#include <linux/panic.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <asm/host.h>
#include <asm/irq_regs.h>
#include <asm/irqflags.h>
#include <asm/ptrace.h>

#define TCPCC_HOST_TEST_IRQ          1
#define TCPCC_HOST_IRQ_TEST_ROUNDS  64
#define TCPCC_HOST_IRQ_DELAY_NS      (1ULL * NSEC_PER_MSEC)

static unsigned long tcpcc_irq_state = ARCH_IRQ_ENABLED;
static int tcpcc_test_irq_fd = -1;
static struct completion tcpcc_test_softirq_done;
static struct tasklet_struct tcpcc_test_tasklet;
static unsigned int tcpcc_test_hardirq_count;
static unsigned int tcpcc_test_softirq_count;
static bool tcpcc_test_softirq_active;

extern void tcpcc_timer_dispatch(void);

unsigned long arch_local_save_flags(void)
{
	return READ_ONCE(tcpcc_irq_state);
}

void arch_local_irq_restore(unsigned long flags)
{
	WRITE_ONCE(tcpcc_irq_state, flags);
}

static void tcpcc_irq_noop(struct irq_data *data)
{
}

static struct irq_chip tcpcc_host_irq_chip = {
	.name = "tcpcc-host",
	.irq_ack = tcpcc_irq_noop,
	.irq_mask = tcpcc_irq_noop,
	.irq_unmask = tcpcc_irq_noop,
};

static void tcpcc_dispatch_host_irq(unsigned int irq)
{
	struct pt_regs regs = { 0 };
	struct pt_regs *old_regs;
	unsigned long flags;
	int ret;

	if (irqs_disabled())
		panic("tcpcc: host IRQ %u dispatch attempted with IRQs disabled", irq);

	local_irq_save(flags);
	old_regs = set_irq_regs(&regs);
	irq_enter();
	ret = generic_handle_irq(irq);
	irq_exit();
	set_irq_regs(old_regs);
	local_irq_restore(flags);

	if (ret)
		panic("tcpcc: generic_handle_irq(%u) failed: %d", irq, ret);
}

void tcpcc_host_idle_wait(void)
{
	u64 token;
	int ret;

	/*
	 * The host may mark fds ready at any time, but it never calls into Linux.
	 * The single vCPU crosses to epoll only from idle with local IRQs masked,
	 * then enables the Linux IRQ state before consuming one pending event.
	 */
	if (!irqs_disabled())
		panic("tcpcc: hosted event wait entered with local IRQs enabled");

	local_irq_enable();
	ret = tcpcc_host_event_wait(&token);
	if (ret)
		panic("tcpcc: host event wait failed: %d", ret);

	if (token == TCPCC_HOST_EVENT_TIMER) {
		tcpcc_timer_dispatch();
		return;
	}

	if (token >= TCPCC_HOST_EVENT_IRQ_BASE &&
	    token < TCPCC_HOST_EVENT_IRQ_BASE + NR_IRQS) {
		tcpcc_dispatch_host_irq((unsigned int)(token - TCPCC_HOST_EVENT_IRQ_BASE));
		return;
	}

	panic("tcpcc: unknown host event token %llu",
	      (unsigned long long)token);
}

void __init init_IRQ(void)
{
	int ret;

	ret = tcpcc_host_event_loop_init();
	if (ret)
		panic("tcpcc: host event-loop initialization failed: %d", ret);

	irq_set_chip_and_handler(TCPCC_HOST_TEST_IRQ, &tcpcc_host_irq_chip,
				 handle_simple_irq);
	irq_clear_status_flags(TCPCC_HOST_TEST_IRQ, IRQ_NOREQUEST | IRQ_NOPROBE);

	pr_notice("tcpcc: M3.4 host epoll event loop initialized\n");
}

static void tcpcc_test_tasklet_fn(struct tasklet_struct *tasklet)
{
	if (!in_serving_softirq())
		panic("tcpcc: M3.4 tasklet ran outside softirq context");
	if (tcpcc_test_softirq_active)
		panic("tcpcc: M3.4 softirq re-entered on single vCPU");
	if (tcpcc_test_softirq_count >= tcpcc_test_hardirq_count)
		panic("tcpcc: M3.4 softirq ran without preceding hardirq");

	tcpcc_test_softirq_active = true;
	tcpcc_test_softirq_count++;
	complete(&tcpcc_test_softirq_done);
	tcpcc_test_softirq_active = false;
}

static irqreturn_t tcpcc_test_irq_handler(int irq, void *dev_id)
{
	u64 expirations;
	int ret;

	if (!in_hardirq())
		panic("tcpcc: M3.4 virtual IRQ handler ran outside hardirq context");

	ret = tcpcc_host_timer_wait(tcpcc_test_irq_fd, &expirations);
	if (ret)
		panic("tcpcc: M3.4 test IRQ source ack failed: %d", ret);
	if (!expirations)
		panic("tcpcc: M3.4 virtual IRQ without host expiration");

	tcpcc_test_hardirq_count++;
	tasklet_schedule(&tcpcc_test_tasklet);
	return IRQ_HANDLED;
}

static int __init tcpcc_irq_event_selftest(void)
{
	unsigned int round;
	int ret;

	init_completion(&tcpcc_test_softirq_done);
	tasklet_setup(&tcpcc_test_tasklet, tcpcc_test_tasklet_fn);

	tcpcc_test_irq_fd = tcpcc_host_timer_create();
	if (tcpcc_test_irq_fd < 0)
		panic("tcpcc: M3.4 test timerfd creation failed: %d",
		      tcpcc_test_irq_fd);

	ret = tcpcc_host_event_add(tcpcc_test_irq_fd,
				   TCPCC_HOST_EVENT_IRQ_BASE + TCPCC_HOST_TEST_IRQ);
	if (ret)
		panic("tcpcc: M3.4 test IRQ source registration failed: %d", ret);

	ret = request_irq(TCPCC_HOST_TEST_IRQ, tcpcc_test_irq_handler,
			  IRQF_NO_THREAD, "tcpcc-m3.4-test", &tcpcc_test_irq_fd);
	if (ret)
		panic("tcpcc: M3.4 request_irq failed: %d", ret);

	pr_notice("tcpcc: M3.4 IRQ/softirq event-loop stress starting\n");

	for (round = 0; round < TCPCC_HOST_IRQ_TEST_ROUNDS; round++) {
		reinit_completion(&tcpcc_test_softirq_done);

		ret = tcpcc_host_timer_arm(tcpcc_test_irq_fd,
					   TCPCC_HOST_IRQ_DELAY_NS);
		if (ret)
			panic("tcpcc: M3.4 host IRQ arm round %u failed: %d",
			      round, ret);

		wait_for_completion(&tcpcc_test_softirq_done);

		if (tcpcc_test_hardirq_count != round + 1 ||
		    tcpcc_test_softirq_count != round + 1)
			panic("tcpcc: M3.4 round %u counts hard=%u soft=%u",
			      round, tcpcc_test_hardirq_count,
			      tcpcc_test_softirq_count);
		if (tcpcc_test_softirq_active)
			panic("tcpcc: M3.4 softirq active leaked past round %u", round);
	}

	disable_irq(TCPCC_HOST_TEST_IRQ);
	ret = tcpcc_host_event_del(tcpcc_test_irq_fd);
	if (ret)
		panic("tcpcc: M3.4 test IRQ source removal failed: %d", ret);
	ret = tcpcc_host_timer_cancel(tcpcc_test_irq_fd);
	if (ret)
		panic("tcpcc: M3.4 test IRQ timer cancel failed: %d", ret);
	free_irq(TCPCC_HOST_TEST_IRQ, &tcpcc_test_irq_fd);
	tasklet_kill(&tcpcc_test_tasklet);
	ret = tcpcc_host_close(tcpcc_test_irq_fd);
	if (ret)
		panic("tcpcc: M3.4 test IRQ fd close failed: %d", ret);
	tcpcc_test_irq_fd = -1;

	pr_notice("tcpcc: M3.4 IRQ/softirq event-loop stress passed (%u rounds)\n",
		  TCPCC_HOST_IRQ_TEST_ROUNDS);
	return 0;
}
postcore_initcall(tcpcc_irq_event_selftest);

int show_interrupts(struct seq_file *p, void *v)
{
	return 0;
}

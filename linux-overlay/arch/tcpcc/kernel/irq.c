// SPDX-License-Identifier: GPL-2.0-only
#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/panic.h>
#include <asm/irqflags.h>

/*
 * The runtime still models one Linux vCPU.  M3.4 will connect host event
 * delivery to this state; host signals/threads must not enter Linux
 * asynchronously before that boundary exists.
 */
static unsigned long tcpcc_irq_state = ARCH_IRQ_ENABLED;

unsigned long arch_local_save_flags(void)
{
	return READ_ONCE(tcpcc_irq_state);
}

void arch_local_irq_restore(unsigned long flags)
{
	WRITE_ONCE(tcpcc_irq_state, flags);
}

void __init init_IRQ(void)
{
	/*
	 * M3.1 stops here deliberately. Reaching this architecture hook proves
	 * that start_kernel() has completed generic MM, scheduler, workqueue and
	 * early RCU initialization using the host-backed memory arena. M3.2-M3.4
	 * replace this stop with timer/task/IRQ runtime semantics.
	 */
	panic("tcpcc: M3.1 reached IRQ boundary after host-backed MM init");
}

int show_interrupts(struct seq_file *p, void *v)
{
	/* There are no host-backed IRQ lines until M3.4. */
	return 0;
}

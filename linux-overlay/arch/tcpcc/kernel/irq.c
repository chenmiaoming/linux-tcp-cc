// SPDX-License-Identifier: GPL-2.0-only
#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <asm/irqflags.h>

/*
 * The runtime still models one Linux vCPU. M3.2 timer delivery is deliberately
 * synchronous: host timer expiry becomes pending state and is dispatched only
 * from an explicit safe point. M3.4 will connect the general host event loop to
 * this local IRQ state and add non-timer IRQ/softirq delivery.
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
	/* M3.2 needs no generic host IRQ lines; the timer is a clockevent source. */
}

int show_interrupts(struct seq_file *p, void *v)
{
	/* There are no host-backed IRQ lines until M3.4. */
	return 0;
}

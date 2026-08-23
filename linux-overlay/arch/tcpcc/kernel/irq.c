// SPDX-License-Identifier: GPL-2.0-only
#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <asm/irqflags.h>

/*
 * M2 models one Linux vCPU and therefore only needs the architectural local
 * IRQ state contract.  M3 will connect host event delivery to this state; host
 * signals/threads must not enter Linux asynchronously before that runtime
 * boundary exists.
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
	/* M3 installs the host event/IRQ injection path. */
}

int show_interrupts(struct seq_file *p, void *v)
{
	/* There are no host-backed IRQ lines in the M2 link substrate. */
	return 0;
}

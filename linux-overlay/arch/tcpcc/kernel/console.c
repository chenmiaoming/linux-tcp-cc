// SPDX-License-Identifier: GPL-2.0-only
#include <linux/console.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/panic_notifier.h>
#include <asm/host.h>

#define TCPCC_M2_PANIC_EXIT_STATUS 86

static void tcpcc_console_write(struct console *con, const char *s,
				unsigned int count)
{
	tcpcc_host_write(s, count);
}

static struct console tcpcc_host_console = {
	.name = "tcpcc",
	.write = tcpcc_console_write,
	/*
	 * This is the hosted kernel's persistent diagnostic console, not a
	 * temporary boot console.  CON_BOOT makes the generic console core
	 * unregister it when tty0 appears during console_init(), which hides all
	 * later milestone diagnostics from the host/CI log.
	 */
	.flags = CON_PRINTBUFFER | CON_ANYTIME | CON_ENABLED,
	.index = -1,
};

void __init tcpcc_host_console_init(void)
{
	register_console(&tcpcc_host_console);
}

static int tcpcc_panic_exit(struct notifier_block *nb,
			    unsigned long event, void *ptr)
{
	static const char marker[] =
		"tcpcc-host: panic boundary -> exit(86)\n";

	/*
	 * Use the raw host channel here instead of printk: this notifier is the
	 * last-resort M2.3 lifecycle boundary and must not depend on console locks.
	 */
	tcpcc_host_write(marker, sizeof(marker) - 1);
	tcpcc_host_exit(TCPCC_M2_PANIC_EXIT_STATUS);
}

static struct notifier_block tcpcc_panic_notifier = {
	.notifier_call = tcpcc_panic_exit,
};

void __init tcpcc_host_install_panic_exit(void)
{
	int ret = atomic_notifier_chain_register(&panic_notifier_list,
						 &tcpcc_panic_notifier);

	if (ret) {
		static const char marker[] =
			"tcpcc-host: panic notifier registration failed\n";

		tcpcc_host_write(marker, sizeof(marker) - 1);
		tcpcc_host_exit(85);
	}
}

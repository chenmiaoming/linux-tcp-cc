// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/panic.h>
#include <linux/printk.h>
#include <asm/host.h>
#include <asm/page.h>

/* Generic NOMMU/block helpers require a page-sized, page-aligned zero page. */
unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
	__aligned(PAGE_SIZE);

void __init setup_arch(char **cmdline_p)
{
	/*
	 * M2.3 deliberately stops inside setup_arch(), before Linux reaches the
	 * memory/timer/scheduler substrate owned by M3.  Registering a boot
	 * console here also flushes the linux_banner that start_kernel() queued
	 * immediately before entering setup_arch().
	 */
	*cmdline_p = boot_command_line;

	tcpcc_host_console_init();
	tcpcc_host_install_panic_exit();

	pr_notice("tcpcc: M2.3 reached setup_arch from hosted start_kernel\n");
	panic("tcpcc: M2.3 deterministic stop before M3 runtime");
}

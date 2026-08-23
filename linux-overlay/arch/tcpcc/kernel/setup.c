// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/mm.h>
#include <asm/page.h>

/* Generic NOMMU/block helpers require a page-sized, page-aligned zero page. */
unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
	__aligned(PAGE_SIZE);

void __init setup_arch(char **cmdline_p)
{
	/*
	 * M2 has no host memory allocator yet.  Establish only the command-line
	 * side of the early architecture contract; M3 will register host-backed
	 * memory before the kernel is allowed to execute start_kernel().
	 */
	*cmdline_p = boot_command_line;
}

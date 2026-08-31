// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <asm/host.h>
#include <asm/page.h>
#include <asm/sections.h>
#include <asm/tcpcc_compat.h>

#define TCPCC_MEMORY_MIB              (1024UL * 1024UL)
#define TCPCC_DEFAULT_MEMORY_MIB      128UL
#define TCPCC_MINIMUM_MEMORY_MIB      128UL
#define TCPCC_MEMORY_ARGUMENT         "--memory-mib="

unsigned long tcpcc_physmem;
unsigned long tcpcc_physmem_size;
unsigned long tcpcc_host_initial_stack;

static void __init tcpcc_paging_init(void)
{
	/*
	 * PFN zero is reserved as a guard and because memblock uses physical
	 * address zero as its allocation-failure sentinel.  All managed pages are
	 * backed by the anonymous host arena mapped below.
	 */
	memblock_add(0, tcpcc_physmem_size);
	memblock_reserve(0, PAGE_SIZE);

	min_low_pfn = 1;
	max_pfn = max_low_pfn = tcpcc_physmem_size >> PAGE_SHIFT;
	high_memory = (void *)(tcpcc_physmem + tcpcc_physmem_size);
	tcpcc_compat_memory_init();
}

static unsigned long __init tcpcc_host_memory_size(void)
{
	unsigned long *stack = (unsigned long *)tcpcc_host_initial_stack;
	unsigned long memory_mib = TCPCC_DEFAULT_MEMORY_MIB;
	unsigned long argc;
	char **argv;
	unsigned long index;

	if (!stack)
		panic("tcpcc: host initial stack is unavailable");
	argc = stack[0];
	if (!argc || argc > 4096)
		panic("tcpcc: invalid host argc %lu", argc);
	argv = (char **)&stack[1];

	for (index = 1; index < argc; index++) {
		unsigned long parsed;
		const char *value;

		if (strncmp(argv[index], TCPCC_MEMORY_ARGUMENT,
			    sizeof(TCPCC_MEMORY_ARGUMENT) - 1))
			continue;
		value = argv[index] + sizeof(TCPCC_MEMORY_ARGUMENT) - 1;
		if (kstrtoul(value, 10, &parsed) ||
		    parsed < TCPCC_MINIMUM_MEMORY_MIB ||
		    parsed > ~0UL / TCPCC_MEMORY_MIB)
			panic("tcpcc: invalid hosted memory argument '%s'",
			      argv[index]);
		memory_mib = parsed;
	}

	return memory_mib * TCPCC_MEMORY_MIB;
}

void __init setup_arch(char **cmdline_p)
{
	unsigned long memory_size;
	void *arena;

	/* Register diagnostics before any host-memory operation can fail. */
	tcpcc_host_console_init();
	tcpcc_host_install_panic_exit();

	memory_size = tcpcc_host_memory_size();
	arena = tcpcc_host_map_anon(memory_size);
	if (!arena)
		panic("tcpcc: unable to map %lu bytes of host-backed RAM",
		      memory_size);

	tcpcc_physmem = (unsigned long)arena;
	tcpcc_physmem_size = memory_size;

	/* The executable image is host-mapped code, not Linux managed RAM. */
	setup_initial_init_mm(_stext, _etext, _edata, NULL);
	tcpcc_paging_init();

	*cmdline_p = boot_command_line;

	pr_notice("tcpcc: M3.1 host RAM %lu MiB at %px, PFNs %lu-%lu\n",
		  tcpcc_physmem_size >> 20, arena, min_low_pfn, max_low_pfn - 1);
	pr_notice("tcpcc: M3.1 setup_arch memory initialization complete\n");
}

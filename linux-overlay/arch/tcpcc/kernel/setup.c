// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <asm/host.h>
#include <asm/page.h>
#include <asm/sections.h>

#define TCPCC_M3_MEMORY_SIZE (128UL * 1024 * 1024)

unsigned long tcpcc_physmem;
unsigned long tcpcc_physmem_size;

/* Generic NOMMU/block helpers require a page-sized, page-aligned zero page. */
unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
	__aligned(PAGE_SIZE);

static void __init tcpcc_paging_init(void)
{
	unsigned long max_zone_pfn[MAX_NR_ZONES] = { 0 };

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

	max_zone_pfn[ZONE_NORMAL] = max_low_pfn;
	free_area_init(max_zone_pfn);
}

void __init setup_arch(char **cmdline_p)
{
	void *arena;

	/* Register diagnostics before any host-memory operation can fail. */
	tcpcc_host_console_init();
	tcpcc_host_install_panic_exit();

	arena = tcpcc_host_map_anon(TCPCC_M3_MEMORY_SIZE);
	if (!arena)
		panic("tcpcc: unable to map %lu bytes of host-backed RAM",
		      TCPCC_M3_MEMORY_SIZE);

	tcpcc_physmem = (unsigned long)arena;
	tcpcc_physmem_size = TCPCC_M3_MEMORY_SIZE;

	/* The executable image is host-mapped code, not Linux managed RAM. */
	setup_initial_init_mm(_stext, _etext, _edata, NULL);
	tcpcc_paging_init();

	*cmdline_p = boot_command_line;

	pr_notice("tcpcc: M3.1 host RAM %lu MiB at %px, PFNs %lu-%lu\n",
		  tcpcc_physmem_size >> 20, arena, min_low_pfn, max_low_pfn - 1);
	pr_notice("tcpcc: M3.1 setup_arch memory initialization complete\n");
}

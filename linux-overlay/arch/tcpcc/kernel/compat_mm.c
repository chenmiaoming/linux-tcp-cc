// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <asm/page.h>
#include <asm/tcpcc_compat.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 3, 0)
/* Generic NOMMU/block helpers require an architecture-owned shared zero page. */
unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
	__aligned(PAGE_SIZE);

void __init tcpcc_compat_memory_init(void)
{
	unsigned long max_zone_pfn[MAX_NR_ZONES] = { 0 };

	max_zone_pfn[ZONE_NORMAL] = max_low_pfn;
	free_area_init(max_zone_pfn);
}
#else
/* Linux 7.3 initializes zones after setup_arch and owns the shared zero page. */
void __init arch_zone_limits_init(unsigned long *max_zone_pfn)
{
	max_zone_pfn[ZONE_NORMAL] = max_low_pfn;
}

void __init tcpcc_compat_memory_init(void)
{
}
#endif

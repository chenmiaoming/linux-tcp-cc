// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/panic.h>
#include <linux/printk.h>
#include <asm/host.h>
#include <asm/page.h>
#include <asm/sections.h>

/*
 * The tcpcc executable image is mapped by the host ELF loader and is not part
 * of tcpcc_physmem.  Generic free_initmem_default() therefore cannot return
 * these pages to the guest buddy allocator: virt_to_page() is defined only for
 * the separate guest-RAM arena.
 *
 * The linker keeps all discardable init sections inside page-aligned bounds.
 * Remove that host mapping outright once generic kernel_init() reaches its
 * normal free_initmem() phase.  A stale post-init reference then faults rather
 * than silently refaulting discarded executable contents.
 */
void free_initmem(void)
{
	unsigned long start = (unsigned long)__init_begin;
	unsigned long end = (unsigned long)__init_end;
	size_t len;
	int ret;

	if (!IS_ALIGNED(start, PAGE_SIZE) || !IS_ALIGNED(end, PAGE_SIZE) ||
	    end <= start)
		panic("tcpcc: invalid init image bounds %px-%px",
		      __init_begin, __init_end);

	len = end - start;
	ret = tcpcc_host_unmap((void *)start, len);
	if (ret)
		panic("tcpcc: unable to unmap %zu bytes of init image: %d",
		      len, ret);

	pr_notice("tcpcc: reclaimed %zu KiB host-mapped init image\n",
		  len >> 10);
}

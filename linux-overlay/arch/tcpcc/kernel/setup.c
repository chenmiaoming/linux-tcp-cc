// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/panic.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <asm/host.h>
#include <asm/page.h>

#define TCPCC_PHYS_MEMORY_BASE   0x00100000UL
#define TCPCC_PHYS_MEMORY_LIMIT  0x10000000UL
#define TCPCC_MEMBLOCK_PROBE_BYTE 0xa5

extern char _text[];
extern char _end[];

/* Generic NOMMU/block helpers require a page-sized, page-aligned zero page. */
unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
	__aligned(PAGE_SIZE);

static void __init tcpcc_early_memory_init(void)
{
	unsigned long image_start = (unsigned long)_text;
	unsigned long image_end = PAGE_ALIGN((unsigned long)_end);
	unsigned char *probe;
	long host_ret;
	int ret;

	/* Keep the identity physical model tied to the linker contract. */
	if (image_start != TCPCC_PHYS_MEMORY_BASE)
		panic("tcpcc: image base %#lx != physical base %#lx",
		      image_start, TCPCC_PHYS_MEMORY_BASE);
	if (image_end >= TCPCC_PHYS_MEMORY_LIMIT)
		panic("tcpcc: image end %#lx exceeds M3.1 memory limit %#lx",
		      image_end, TCPCC_PHYS_MEMORY_LIMIT);

	/*
	 * The ELF loader already mapped [image_start, image_end). Map only the
	 * anonymous tail. MAP_FIXED_NOREPLACE in the host boundary guarantees
	 * that this cannot silently clobber another host mapping.
	 */
	host_ret = tcpcc_host_map_memory(image_end, TCPCC_PHYS_MEMORY_LIMIT);
	if (host_ret)
		panic("tcpcc: host RAM mapping [%#lx-%#lx) failed: %ld",
		      image_end, TCPCC_PHYS_MEMORY_LIMIT, host_ret);

	ret = memblock_add(TCPCC_PHYS_MEMORY_BASE,
			   TCPCC_PHYS_MEMORY_LIMIT - TCPCC_PHYS_MEMORY_BASE);
	if (ret)
		panic("tcpcc: memblock_add failed: %d", ret);

	/* Never allow an early allocator to reuse the loaded kernel image. */
	ret = memblock_reserve(TCPCC_PHYS_MEMORY_BASE,
			       image_end - TCPCC_PHYS_MEMORY_BASE);
	if (ret)
		panic("tcpcc: memblock_reserve image failed: %d", ret);

	pr_notice("tcpcc: M3.1 host memory [%#lx-%#lx), image reserved through %#lx\n",
		  TCPCC_PHYS_MEMORY_BASE, TCPCC_PHYS_MEMORY_LIMIT, image_end);

	/*
	 * Exercise the same upstream early allocator that setup_command_line()
	 * will consume in M3.2. The allocation itself remains reserved.
	 */
	probe = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
	if (!probe)
		panic("tcpcc: M3.1 memblock probe allocation failed");
	if ((unsigned long)probe < image_end ||
	    (unsigned long)probe + PAGE_SIZE > TCPCC_PHYS_MEMORY_LIMIT)
		panic("tcpcc: M3.1 memblock probe outside host RAM: %px", probe);

	memset(probe, TCPCC_MEMBLOCK_PROBE_BYTE, PAGE_SIZE);
	if (probe[0] != TCPCC_MEMBLOCK_PROBE_BYTE ||
	    probe[PAGE_SIZE - 1] != TCPCC_MEMBLOCK_PROBE_BYTE)
		panic("tcpcc: M3.1 memblock probe readback failed");

	pr_notice("tcpcc: M3.1 memblock probe passed at %px\n", probe);
}

void __init setup_arch(char **cmdline_p)
{
	/*
	 * M3.1 still stops inside setup_arch(). It adds only real host-backed
	 * early memory and upstream memblock semantics; generic buddy/slab,
	 * timing and scheduling bring-up remain later M3 subtasks.
	 */
	*cmdline_p = boot_command_line;

	tcpcc_host_console_init();
	tcpcc_host_install_panic_exit();

	/* Preserve the M2.3 proof that execution entered upstream start_kernel(). */
	pr_notice("tcpcc: M2.3 reached setup_arch from hosted start_kernel\n");

	tcpcc_early_memory_init();
	panic("tcpcc: M3.1 deterministic stop after memblock bootstrap");
}

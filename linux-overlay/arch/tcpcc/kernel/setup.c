// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/panic.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <asm/host.h>
#include <asm/page.h>

#define TCPCC_IMAGE_BASE          0x00100000UL
#define TCPCC_HOST_RAM_BASE       0x01000000UL
#define TCPCC_HOST_RAM_SIZE       (16UL * 1024 * 1024)
#define TCPCC_HOST_RAM_LIMIT      (TCPCC_HOST_RAM_BASE + TCPCC_HOST_RAM_SIZE)
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

	/* Keep the hosted ELF image and allocatable Linux RAM disjoint. */
	if (image_start != TCPCC_IMAGE_BASE)
		panic("tcpcc: image base %#lx != linker base %#lx",
		      image_start, TCPCC_IMAGE_BASE);
	if (image_end > TCPCC_HOST_RAM_BASE)
		panic("tcpcc: image end %#lx overlaps host RAM base %#lx",
		      image_end, TCPCC_HOST_RAM_BASE);

	/*
	 * The host ELF loader owns the kernel image mappings. Linux physical RAM
	 * is a separate, fixed 16 MiB anonymous arena. Keeping the resources
	 * disjoint avoids coupling the runtime allocator to PT_LOAD alignment or
	 * to linker orphan-section placement while preserving the M3 NOMMU
	 * identity-mapping model.
	 */
	host_ret = tcpcc_host_map_memory(TCPCC_HOST_RAM_BASE,
					 TCPCC_HOST_RAM_LIMIT);
	if (host_ret)
		panic("tcpcc: host RAM mapping [%#lx-%#lx) failed: %ld",
		      TCPCC_HOST_RAM_BASE, TCPCC_HOST_RAM_LIMIT, host_ret);

	ret = memblock_add(TCPCC_HOST_RAM_BASE, TCPCC_HOST_RAM_SIZE);
	if (ret)
		panic("tcpcc: memblock_add failed: %d", ret);

	/*
	 * Record the loaded image as reserved even though it is deliberately
	 * outside the usable RAM list. This makes the exclusion explicit in
	 * memblock provenance and protects the contract if memory layout grows.
	 */
	ret = memblock_reserve(image_start, image_end - image_start);
	if (ret)
		panic("tcpcc: memblock_reserve image failed: %d", ret);

	pr_notice("tcpcc: M3.1 host RAM [%#lx-%#lx), kernel image [%#lx-%#lx) excluded\n",
		  TCPCC_HOST_RAM_BASE, TCPCC_HOST_RAM_LIMIT,
		  image_start, image_end);

	/*
	 * Exercise the same upstream early allocator that setup_command_line()
	 * will consume in M3.2. The allocation itself remains reserved.
	 */
	probe = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
	if (!probe)
		panic("tcpcc: M3.1 memblock probe allocation failed");
	if ((unsigned long)probe < TCPCC_HOST_RAM_BASE ||
	    (unsigned long)probe + PAGE_SIZE > TCPCC_HOST_RAM_LIMIT)
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

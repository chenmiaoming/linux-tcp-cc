/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Minimal final-link layout for the Linux 6.18 tcpcc architecture.
 *
 * tcpcc is compiled with the host x86-64 toolchain, so the M2 validation
 * image is a normal fully linked ELF64/x86-64 kernel image.  This is not the
 * eventual host process ABI and does not use LKL's relocatable (-r) link.
 */
#include <asm-generic/vmlinux.lds.h>
#include <asm/page.h>
#include <asm/cache.h>
#include <asm/thread_info.h>

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(start_kernel)

jiffies = jiffies_64;

SECTIONS
{
	/*
	 * M2 assigns a deterministic, page-aligned link address only so the
	 * final ELF has concrete section addresses.  Host mapping/relocation is
	 * deliberately a later runtime contract.
	 */
	. = 0x100000;
	. = ALIGN(PAGE_SIZE);

	_text = .;
	_stext = .;
	HEAD_TEXT_SECTION
	INIT_TEXT_SECTION(PAGE_SIZE)

	.text : {
		TEXT_TEXT
		SCHED_TEXT
		LOCK_TEXT
		IRQENTRY_TEXT
		SOFTIRQENTRY_TEXT
	}
	_etext = .;

	. = ALIGN(PAGE_SIZE);
	__init_begin = .;
	INIT_DATA_SECTION(PAGE_SIZE)
	PERCPU_SECTION(L1_CACHE_BYTES)
	__init_end = .;

	_sdata = .;
	RO_DATA(PAGE_SIZE)
	RW_DATA(L1_CACHE_BYTES, PAGE_SIZE, THREAD_SIZE)
	_edata = .;

	EXCEPTION_TABLE(16)
	NOTES

	/* PIC compilation can emit a GOT even though the final M2 image is static. */
	.got : { *(.got.plt) *(.igot.plt) *(.got) *(.igot) }

	BSS_SECTION(0, 0, 0)
	_end = .;

	STABS_DEBUG
	DWARF_DEBUG
	MODINFO
	ELF_DETAILS

	DISCARDS
}

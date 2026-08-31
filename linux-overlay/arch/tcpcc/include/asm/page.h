/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_PAGE_H
#define _ASM_TCPCC_PAGE_H

#include <vdso/page.h>
#define ARCH_PFN_OFFSET 0UL

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/string.h>

/*
 * Hosted physical memory is an offset space backed by one contiguous host
 * mapping.  This follows the same core model as UML: Linux PFNs stay compact
 * regardless of where the host chooses to mmap the arena.
 */
extern unsigned long tcpcc_physmem;
extern unsigned long tcpcc_physmem_size;

#define PAGE_OFFSET tcpcc_physmem

#define clear_page(page) memset((page), 0, PAGE_SIZE)
#define copy_page(to, from) memcpy((to), (from), PAGE_SIZE)
#define clear_user_page(page, vaddr, pg) clear_page(page)
#define copy_user_page(to, from, vaddr, pg) copy_page((to), (from))

typedef struct { unsigned long pte; } pte_t;
typedef struct { unsigned long pmd; } pmd_t;
typedef struct { unsigned long pgd; } pgd_t;
typedef struct { unsigned long pgprot; } pgprot_t;
typedef struct page *pgtable_t;

#define pte_val(x) ((x).pte)
#define pmd_val(x) ((x).pmd)
#define pgd_val(x) ((x).pgd)
#define pgprot_val(x) ((x).pgprot)
#define __pte(x) ((pte_t){ (x) })
#define __pmd(x) ((pmd_t){ (x) })
#define __pgd(x) ((pgd_t){ (x) })
#define __pgprot(x) ((pgprot_t){ (x) })

static inline unsigned long __tcpcc_pa(const void *addr)
{
	return (unsigned long)addr - tcpcc_physmem;
}

static inline void *__tcpcc_va(unsigned long phys)
{
	return (void *)(tcpcc_physmem + phys);
}

#define __pa(x) __tcpcc_pa((const void *)(x))
#define __va(x) __tcpcc_va((unsigned long)(x))
#define virt_to_phys(x) __pa(x)
#define phys_to_virt(x) __va(x)

static inline unsigned long virt_to_pfn(const void *addr)
{
	return __pa(addr) >> PAGE_SHIFT;
}
#define virt_to_pfn virt_to_pfn

static inline void *pfn_to_virt(unsigned long pfn)
{
	return __va(pfn << PAGE_SHIFT);
}
#define pfn_to_virt pfn_to_virt

#define virt_to_page(addr) pfn_to_page(virt_to_pfn(addr))
#define page_to_virt(page) pfn_to_virt(page_to_pfn(page))

static inline bool virt_addr_valid(const void *addr)
{
	unsigned long v = (unsigned long)addr;

	return v >= tcpcc_physmem && v < tcpcc_physmem + tcpcc_physmem_size;
}
#define virt_addr_valid virt_addr_valid
#else
#define PAGE_OFFSET 0UL
#endif

#include <asm-generic/memory_model.h>
#include <asm-generic/getorder.h>

#endif

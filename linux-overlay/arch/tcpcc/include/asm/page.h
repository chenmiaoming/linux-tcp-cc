/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_PAGE_H
#define _ASM_TCPCC_PAGE_H

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_OFFSET 0UL
#define ARCH_PFN_OFFSET 0UL

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/string.h>

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

#define __pa(x) ((unsigned long)(x))
#define __va(x) ((void *)((unsigned long)(x)))

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
#define virt_addr_valid(addr) (1)
#endif

#include <asm-generic/memory_model.h>
#include <asm-generic/getorder.h>

#endif

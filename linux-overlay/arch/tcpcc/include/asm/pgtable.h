/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_PGTABLE_H
#define _ASM_TCPCC_PGTABLE_H

/*
 * Initial tcpcc bring-up is NOMMU: Linux virtual addresses are hosted process
 * addresses and there is no guest page-table walk. This follows the current
 * Linux 6.18 NOMMU pattern (for example m68k pgtable_no.h) rather than
 * inventing an MMU implementation that the runtime does not have.
 */
#include <asm-generic/pgtable-nopud.h>
#include <asm/page.h>

#define pgd_present(pgd) (1)
#define pgd_none(pgd)    (0)
#define pgd_bad(pgd)     (0)
#define pgd_clear(pgdp)  do { } while (0)
#define pmd_offset(a, b) ((void *)0)

#define PAGE_NONE       __pgprot(0)
#define PAGE_SHARED     __pgprot(0)
#define PAGE_COPY       __pgprot(0)
#define PAGE_READONLY   __pgprot(0)
#define PAGE_KERNEL     __pgprot(0)

#define swapper_pg_dir ((pgd_t *)0)

extern void *empty_zero_page;
#define ZERO_PAGE(vaddr) (virt_to_page(empty_zero_page))

/* No separate vmalloc/kmap address space exists in the NOMMU hosted model. */
#define VMALLOC_START 0UL
#define VMALLOC_END   (~0UL)
#define KMAP_START    0UL
#define KMAP_END      (~0UL)

#endif /* _ASM_TCPCC_PGTABLE_H */

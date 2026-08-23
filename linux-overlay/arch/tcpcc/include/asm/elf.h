/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_ELF_H
#define _ASM_TCPCC_ELF_H

#include <uapi/linux/elf.h>

/*
 * The tcpcc runtime does not execute guest ELF userspace binaries. Provide the
 * architecture definitions required by generic kernel headers, while rejecting
 * every userspace ELF machine type until a guest ABI is deliberately added.
 */
#define elf_check_arch(hdr) (0)

#define ELF_CLASS ELFCLASS64
#define ELF_DATA  ELFDATA2LSB
#define ELF_ARCH  EM_NONE

/* Core-dump support is disabled for this architecture, but generic headers
 * still require the register-set types to exist at compile time. */
typedef unsigned long elf_greg_t;
typedef elf_greg_t elf_gregset_t[1];
#define ELF_NGREG 1
typedef unsigned long elf_fpregset_t;

#endif /* _ASM_TCPCC_ELF_H */

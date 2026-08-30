/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_HOST_MMAN_H
#define _ASM_TCPCC_HOST_MMAN_H

/* Linux x86-64 host mmap(2) ABI flags used by the hosted memory arena. */
#define TCPCC_HOST_MAP_PRIVATE		0x02
#define TCPCC_HOST_MAP_ANONYMOUS		0x20
#define TCPCC_HOST_MAP_NORESERVE	0x4000

/* Linux x86-64 host madvise(2) advice used for guest-free pages. */
#define TCPCC_HOST_MADV_DONTNEED	4

#define TCPCC_HOST_MAP_ANON_FLAGS	(TCPCC_HOST_MAP_PRIVATE | \
					 TCPCC_HOST_MAP_ANONYMOUS | \
					 TCPCC_HOST_MAP_NORESERVE)

#endif /* _ASM_TCPCC_HOST_MMAN_H */

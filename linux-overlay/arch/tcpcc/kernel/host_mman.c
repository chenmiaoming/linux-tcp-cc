// SPDX-License-Identifier: GPL-2.0-only
#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/host.h>

#if !defined(__x86_64__)
#error "tcpcc host ABI currently requires an x86-64 Linux host"
#endif

/* Linux x86-64 host munmap(2) ABI. */
#define TCPCC_HOST_NR_MUNMAP 11

static __always_inline long tcpcc_host_mman_syscall2(long nr, long arg0,
					      long arg1)
{
	long ret;

	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1)
		     : "rcx", "r11", "memory");
	return ret;
}

int tcpcc_host_unmap(void *address, size_t len)
{
	long ret = tcpcc_host_mman_syscall2(TCPCC_HOST_NR_MUNMAP,
					    (long)address, (long)len);

	return ret < 0 ? (int)ret : 0;
}

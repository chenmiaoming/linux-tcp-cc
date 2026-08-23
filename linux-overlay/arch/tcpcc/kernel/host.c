// SPDX-License-Identifier: GPL-2.0-only
#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/host.h>

#if !defined(__x86_64__)
#error "M2.3 tcpcc host ABI currently requires an x86-64 Linux host"
#endif

/* Linux x86-64 host syscall ABI. Keep this private to arch/tcpcc. */
#define TCPCC_HOST_NR_WRITE       1
#define TCPCC_HOST_NR_EXIT_GROUP  231
#define TCPCC_HOST_STDERR_FILENO  2

static __always_inline long tcpcc_host_syscall1(long nr, long arg0)
{
	long ret;

	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0)
		     : "rcx", "r11", "memory");
	return ret;
}

static __always_inline long tcpcc_host_syscall3(long nr, long arg0,
					 long arg1, long arg2)
{
	long ret;

	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "rcx", "r11", "memory");
	return ret;
}

void tcpcc_host_write(const char *buf, size_t len)
{
	while (len) {
		long ret = tcpcc_host_syscall3(TCPCC_HOST_NR_WRITE,
					       TCPCC_HOST_STDERR_FILENO,
					       (long)buf, (long)len);

		/* A failed host write must never recurse back through printk. */
		if (ret <= 0)
			return;

		buf += ret;
		len -= ret;
	}
}

void __noreturn tcpcc_host_exit(int status)
{
	(void)tcpcc_host_syscall1(TCPCC_HOST_NR_EXIT_GROUP, status & 0xff);

	/* exit_group() should not return. Keep failure deterministic if it does. */
	for (;;)
		asm volatile("pause" ::: "memory");
}

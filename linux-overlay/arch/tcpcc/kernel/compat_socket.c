// SPDX-License-Identifier: GPL-2.0-only
#include <linux/net.h>
#include <linux/version.h>

#include <asm/tcpcc_compat.h>

int tcpcc_compat_kernel_bind(struct socket *sock, void *addr, int addrlen)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 3, 0)
	return kernel_bind(sock, (struct sockaddr_unsized *)addr, addrlen);
#else
	return kernel_bind(sock, (struct sockaddr *)addr, addrlen);
#endif
}

int tcpcc_compat_kernel_connect(struct socket *sock, void *addr, int addrlen,
				int flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 3, 0)
	return kernel_connect(sock, (struct sockaddr_unsized *)addr, addrlen,
			      flags);
#else
	return kernel_connect(sock, (struct sockaddr *)addr, addrlen, flags);
#endif
}

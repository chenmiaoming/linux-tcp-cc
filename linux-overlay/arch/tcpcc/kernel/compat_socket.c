// SPDX-License-Identifier: GPL-2.0-only
#include <linux/net.h>

#include <asm/tcpcc_compat.h>

/*
 * Stable kernels may backport the bind/connect address-type changes
 * independently. Let the actual kernel prototypes convert the void pointer.
 */
int tcpcc_compat_kernel_bind(struct socket *sock, void *addr, int addrlen)
{
	return kernel_bind(sock, addr, addrlen);
}

int tcpcc_compat_kernel_connect(struct socket *sock, void *addr, int addrlen,
				int flags)
{
	return kernel_connect(sock, addr, addrlen, flags);
}

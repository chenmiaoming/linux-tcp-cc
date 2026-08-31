/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_COMPAT_H
#define _ASM_TCPCC_COMPAT_H

#include <linux/types.h>

struct in6_addr;
struct net_device;
struct socket;

/*
 * Keep direct use of unstable networking internals behind this boundary.
 * A new upstream kernel should adapt this implementation before changing the
 * hosted L3 driver or its control ABI.
 */
int tcpcc_compat_configure_ipv4(struct net_device *dev, u32 address,
				u32 prefix_len);
int tcpcc_compat_add_default_route_ipv4(struct net_device *dev, u32 address);
int tcpcc_compat_configure_ipv6(struct net_device *dev,
				const struct in6_addr *address, u32 prefix_len);
int tcpcc_compat_add_default_route_ipv6(struct net_device *dev,
					  const struct in6_addr *address);
int tcpcc_compat_validate_fq_qdisc(struct net_device *dev);
void tcpcc_compat_configure_tcp_wmem(void);
void tcpcc_compat_memory_init(void);
bool tcpcc_compat_hrtimer_is_highres(void);
int tcpcc_compat_kernel_bind(struct socket *sock, void *addr, int addrlen);
int tcpcc_compat_kernel_connect(struct socket *sock, void *addr, int addrlen,
				int flags);

#endif /* _ASM_TCPCC_COMPAT_H */

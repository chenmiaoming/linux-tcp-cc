// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/if_addr.h>
#include <linux/in.h>
#include <linux/inetdevice.h>
#include <linux/ipv6.h>
#include <linux/mm.h>
#include <linux/netdevice.h>
#include <linux/printk.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/string.h>
#include <net/addrconf.h>
#include <net/ip_fib.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/net_namespace.h>
#include <net/sch_generic.h>
#include <net/tcp.h>
#include <asm/tcpcc_compat.h>

#define TCPCC_TCP_WMEM_MAX_DEFAULT (4U * 1024U * 1024U)
#define TCPCC_TCP_WMEM_MAX_LOW_MEMORY (2U * 1024U * 1024U)
#define TCPCC_LOW_MEMORY_PAGES ((128UL * 1024UL * 1024UL) / PAGE_SIZE)

void tcpcc_compat_configure_tcp_wmem(void)
{
	unsigned long ram_pages = totalram_pages();
	bool low_memory = ram_pages <= TCPCC_LOW_MEMORY_PAGES;
	int old_max = READ_ONCE(init_net.ipv4.sysctl_tcp_wmem[2]);
	int target_max = low_memory ? TCPCC_TCP_WMEM_MAX_LOW_MEMORY :
		TCPCC_TCP_WMEM_MAX_DEFAULT;
	int new_max = max_t(int, old_max, target_max);

	/*
	 * tcp_init() normally caps tcp_wmem[2] at 4 MiB, but also limits it
	 * to roughly 1/128 of free RAM. TCPCC's deliberately small 128-MiB
	 * arena therefore leaves a public BBR sender with only about 1 MiB,
	 * even when most of the arena is free. On a high-RTT path the skb
	 * accounting overhead and BBR's 3*cwnd provisioning turn that policy
	 * into a throughput ceiling.
	 *
	 * A 4-MiB ceiling restored upstream-scale throughput in hosted BBR,
	 * but real 128-MiB OpenVZ qualification also showed runs approaching
	 * the outer container's physical-page limit and reporting TCP memory
	 * exhaustion. Use a 2-MiB experimental ceiling for the 128-MiB profile
	 * while retaining 4 MiB for larger arenas. Buffers still grow only on
	 * demand and tcp_mem remains the shared hard-pressure governor.
	 */
	WRITE_ONCE(init_net.ipv4.sysctl_tcp_wmem[2], new_max);
	pr_notice("tcpcc: TCP send-buffer ceiling %d -> %d bytes (%s, on-demand, tcp_mem-governed)\n",
		  old_max, new_max,
		  low_memory ? "low-memory profile" : "default profile");
	pr_notice("tcpcc: TCP memory policy ram_pages=%lu tcp_mem=%ld/%ld/%ld tcp_wmem=%d/%d/%d pressure=%lu\n",
		  ram_pages, READ_ONCE(sysctl_tcp_mem[0]), READ_ONCE(sysctl_tcp_mem[1]),
		  READ_ONCE(sysctl_tcp_mem[2]),
		  READ_ONCE(init_net.ipv4.sysctl_tcp_wmem[0]),
		  READ_ONCE(init_net.ipv4.sysctl_tcp_wmem[1]),
		  READ_ONCE(init_net.ipv4.sysctl_tcp_wmem[2]),
		  READ_ONCE(tcp_memory_pressure));
}

int tcpcc_compat_configure_ipv4(struct net_device *dev, u32 address,
				u32 prefix_len)
{
	struct sockaddr_in *sin;
	struct ifreq ifr;
	int ret;

	if (!prefix_len || prefix_len > 32)
		return -EINVAL;

	rtnl_lock();
	ret = dev_open(dev, NULL);
	rtnl_unlock();
	if (ret)
		return ret;

	memset(&ifr, 0, sizeof(ifr));
	strscpy(ifr.ifr_name, dev->name, IFNAMSIZ);
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(address);
	ret = devinet_ioctl(&init_net, SIOCSIFADDR, &ifr);
	if (ret)
		return ret;

	memset(&ifr, 0, sizeof(ifr));
	strscpy(ifr.ifr_name, dev->name, IFNAMSIZ);
	sin = (struct sockaddr_in *)&ifr.ifr_netmask;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_make_mask(prefix_len);
	return devinet_ioctl(&init_net, SIOCSIFNETMASK, &ifr);
}

int tcpcc_compat_add_default_route_ipv4(struct net_device *dev, u32 address)
{
	struct fib_config config = {
		.fc_dst_len = 0,
		.fc_protocol = RTPROT_BOOT,
		.fc_scope = RT_SCOPE_LINK,
		.fc_type = RTN_UNICAST,
		.fc_table = RT_TABLE_MAIN,
		.fc_oif = dev->ifindex,
		.fc_prefsrc = htonl(address),
		.fc_nlflags = NLM_F_CREATE | NLM_F_EXCL,
		.fc_nlinfo = {
			.nl_net = &init_net,
		},
	};
	struct fib_table *table;
	int ret;

	/* A point-to-point raw-IP device needs a device route, not an ARP peer. */
	rtnl_lock();
	table = fib_new_table(&init_net, RT_TABLE_MAIN);
	ret = table ? fib_table_insert(&init_net, table, &config, NULL) : -ENOBUFS;
	rtnl_unlock();
	if (!ret)
		pr_notice("tcpcc: M8.4 default IPv4 route active on %s\n",
			  dev->name);
	return ret;
}

int tcpcc_compat_configure_ipv6(struct net_device *dev,
				const struct in6_addr *address, u32 prefix_len)
{
	int ret;

	if (!prefix_len || prefix_len > 128 || ipv6_addr_any(address) ||
	    ipv6_addr_is_multicast(address))
		return -EINVAL;

	rtnl_lock();
	ret = dev_open(dev, NULL);
	rtnl_unlock();
	if (ret)
		return ret;

	/* A point-to-point TUN has no neighbour discovery peer; skip DAD. */
	return addrconf_add_dev_addr(&init_net, dev, address, prefix_len,
				     IFA_F_NODAD);
}

int tcpcc_compat_add_default_route_ipv6(struct net_device *dev,
					  const struct in6_addr *address)
{
	struct fib6_config config = {
		.fc_table = RT6_TABLE_MAIN,
		.fc_metric = IP6_RT_PRIO_USER,
		.fc_dst_len = 0,
		.fc_ifindex = dev->ifindex,
		.fc_flags = RTF_UP | RTF_DEFAULT,
		.fc_protocol = RTPROT_BOOT,
		.fc_type = RTN_UNICAST,
		.fc_prefsrc = *address,
		.fc_nlinfo = {
			.nl_net = &init_net,
		},
	};
	int ret;

	ret = ip6_route_add(&config, GFP_KERNEL, NULL);
	if (!ret)
		pr_notice("tcpcc: default IPv6 route active on %s\n", dev->name);
	return ret;
}

int tcpcc_compat_validate_fq_qdisc(struct net_device *dev)
{
	struct Qdisc *qdisc;
	int ret = 0;

	rtnl_lock();
	qdisc = rtnl_dereference(dev->qdisc);
	if (!qdisc || !qdisc->ops || strcmp(qdisc->ops->id, "fq"))
		ret = -EINVAL;
	else
		pr_notice("tcpcc: M6.1 root qdisc fq active on %s\n", dev->name);
	rtnl_unlock();

	return ret;
}

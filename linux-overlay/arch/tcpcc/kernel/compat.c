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

#define TCPCC_TCP_WMEM_MAX_32M   (512U * 1024U)
#define TCPCC_TCP_WMEM_MAX_64M   (1024U * 1024U)
#define TCPCC_TCP_WMEM_MAX_128M  (2U * 1024U * 1024U)
#define TCPCC_TCP_WMEM_MAX_LARGE (4U * 1024U * 1024U)
#define TCPCC_RAM_PAGES(mib) (((mib) * 1024UL * 1024UL) >> PAGE_SHIFT)

static int tcpcc_auto_tcp_wmem_max(unsigned long ram_pages)
{
	if (ram_pages <= TCPCC_RAM_PAGES(32UL))
		return TCPCC_TCP_WMEM_MAX_32M;
	if (ram_pages <= TCPCC_RAM_PAGES(64UL))
		return TCPCC_TCP_WMEM_MAX_64M;
	if (ram_pages <= TCPCC_RAM_PAGES(128UL))
		return TCPCC_TCP_WMEM_MAX_128M;
	return TCPCC_TCP_WMEM_MAX_LARGE;
}

void tcpcc_compat_configure_tcp_wmem(void)
{
	unsigned long ram_pages = totalram_pages();
	unsigned long requested_kib = READ_ONCE(tcpcc_tcp_wmem_max_kib);
	unsigned long ram_mib = (ram_pages << PAGE_SHIFT) >> 20;
	int old_max = READ_ONCE(init_net.ipv4.sysctl_tcp_wmem[2]);
	int target_max = requested_kib ? (int)(requested_kib * 1024UL) :
		tcpcc_auto_tcp_wmem_max(ram_pages);
	const char *policy = requested_kib ? "explicit" : "auto";

	/*
	 * tcp_init() derives tcp_wmem[2] from the hosted RAM size. That is a
	 * sensible safety default, but it is too small for high-BDP BBR at the
	 * tiny RAM sizes tcpcc targets. Keep a RAM-sized auto policy that doubles
	 * from 512 KiB at 32 MiB through the ordinary 4-MiB Linux ceiling above
	 * 128 MiB, and permit an explicit CLI override for qualification.
	 *
	 * This changes only the autotuning ceiling. Socket buffers still grow on
	 * demand, while tcp_mem remains the shared TCP pressure governor.
	 */
	WRITE_ONCE(init_net.ipv4.sysctl_tcp_wmem[2], target_max);
	pr_notice("tcpcc: TCP send-buffer ceiling %d -> %d bytes (%s, hosted RAM %lu MiB, on-demand, tcp_mem-governed)\n",
		  old_max, target_max, policy, ram_mib);
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

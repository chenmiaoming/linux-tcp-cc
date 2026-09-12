// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/if_addr.h>
#include <linux/in.h>
#include <linux/inetdevice.h>
#include <linux/ipv6.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/netdevice.h>
#include <linux/printk.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/string.h>
#include <linux/vmstat.h>
#include <linux/workqueue.h>
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
#define TCPCC_TCP_MEM_PRESSURE_WMEM_MULTIPLIER 8UL
#define TCPCC_TCP_MEM_PRESSURE_RAM_DIVISOR 8UL
#define TCPCC_MEMORY_TELEMETRY_INTERVAL (10 * HZ)

static bool tcpcc_memory_telemetry_started;
static void tcpcc_memory_telemetry_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(tcpcc_memory_telemetry_work,
			    tcpcc_memory_telemetry_workfn);

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

static void tcpcc_compat_configure_tcp_mem(unsigned long ram_pages,
					    int target_wmem_max)
{
	long old_low = READ_ONCE(sysctl_tcp_mem[0]);
	long old_pressure = READ_ONCE(sysctl_tcp_mem[1]);
	long old_high = READ_ONCE(sysctl_tcp_mem[2]);
	unsigned long wmem_pages;
	unsigned long pressure_floor;
	unsigned long pressure_cap;
	long new_low;
	long new_pressure;
	long new_high;

	/*
	 * tcp_init() sizes tcp_mem and tcp_wmem from the same hosted RAM pool.
	 * tcpcc intentionally raises tcp_wmem[2] on tiny guests so high-BDP
	 * senders are not capped by the ordinary small-RAM autotune result.  If
	 * tcp_mem is left untouched, a single sender can then cross the global
	 * TCP pressure threshold while most guest RAM is still free.
	 *
	 * Keep the global budget coordinated with the chosen send ceiling: aim
	 * for a pressure threshold of eight send ceilings, close to the stock
	 * ratio on a 512-MiB guest, but cap the pressure point at 12.5% of hosted
	 * RAM.  Preserve Linux's low:pressure:high shape of 3/4 : 1 : 3/2 and
	 * never lower an upstream-derived threshold.
	 */
	wmem_pages = DIV_ROUND_UP((unsigned long)target_wmem_max, PAGE_SIZE);
	pressure_cap = max_t(unsigned long, 1,
			     ram_pages / TCPCC_TCP_MEM_PRESSURE_RAM_DIVISOR);
	pressure_floor = min_t(unsigned long,
			       wmem_pages * TCPCC_TCP_MEM_PRESSURE_WMEM_MULTIPLIER,
			       pressure_cap);
	new_pressure = max_t(long, old_pressure, (long)pressure_floor);
	new_low = max_t(long, old_low, (new_pressure * 3L) / 4L);
	new_high = max_t(long, old_high, new_low * 2L);

	WRITE_ONCE(sysctl_tcp_mem[0], new_low);
	WRITE_ONCE(sysctl_tcp_mem[1], new_pressure);
	WRITE_ONCE(sysctl_tcp_mem[2], new_high);
	pr_notice("tcpcc: TCP memory budget %ld/%ld/%ld -> %ld/%ld/%ld pages (send-buffer coordinated, pressure cap 12.5%% hosted RAM)\n",
		  old_low, old_pressure, old_high,
		  new_low, new_pressure, new_high);
}

void tcpcc_compat_log_memory_state(const char *phase)
{
	unsigned long total_pages = totalram_pages();
	unsigned long free_pages = global_zone_page_state(NR_FREE_PAGES);
	long available_pages = si_mem_available();
	unsigned long file_pages = global_node_page_state(NR_FILE_PAGES);
	unsigned long slab_reclaimable_pages =
		global_node_page_state_pages(NR_SLAB_RECLAIMABLE_B);
	unsigned long slab_unreclaimable_pages =
		global_node_page_state_pages(NR_SLAB_UNRECLAIMABLE_B);
	long tcp_allocated_pages = tcp_prot.memory_allocated ?
		atomic_long_read(tcp_prot.memory_allocated) : -1L;

	pr_notice("tcpcc: memory snapshot phase=%s total_pages=%lu free_pages=%lu available_pages=%ld file_pages=%lu slab_reclaimable_pages=%lu slab_unreclaimable_pages=%lu tcp_allocated_pages=%ld tcp_mem=%ld/%ld/%ld tcp_wmem=%d/%d/%d pressure=%lu\n",
		  phase ? phase : "unknown", total_pages, free_pages,
		  available_pages, file_pages, slab_reclaimable_pages,
		  slab_unreclaimable_pages, tcp_allocated_pages,
		  READ_ONCE(sysctl_tcp_mem[0]), READ_ONCE(sysctl_tcp_mem[1]),
		  READ_ONCE(sysctl_tcp_mem[2]),
		  READ_ONCE(init_net.ipv4.sysctl_tcp_wmem[0]),
		  READ_ONCE(init_net.ipv4.sysctl_tcp_wmem[1]),
		  READ_ONCE(init_net.ipv4.sysctl_tcp_wmem[2]),
		  READ_ONCE(tcp_memory_pressure));
}

static void tcpcc_memory_telemetry_workfn(struct work_struct *work)
{
	(void)work;
	tcpcc_compat_log_memory_state("runtime");
	schedule_delayed_work(&tcpcc_memory_telemetry_work,
			      TCPCC_MEMORY_TELEMETRY_INTERVAL);
}

static void tcpcc_compat_start_memory_telemetry(void)
{
	if (READ_ONCE(tcpcc_memory_telemetry_started))
		return;
	WRITE_ONCE(tcpcc_memory_telemetry_started, true);
	tcpcc_compat_log_memory_state("runtime-start");
	schedule_delayed_work(&tcpcc_memory_telemetry_work,
			      TCPCC_MEMORY_TELEMETRY_INTERVAL);
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
	 * This changes only the autotuning ceiling; socket buffers still grow on
	 * demand.  Coordinate tcp_mem with the raised ceiling so the shared TCP
	 * pressure governor does not trip solely because tcp_wmem was enlarged,
	 * while bounding that pressure point to 12.5% of hosted RAM.
	 */
	WRITE_ONCE(init_net.ipv4.sysctl_tcp_wmem[2], target_max);
	tcpcc_compat_configure_tcp_mem(ram_pages, target_max);
	pr_notice("tcpcc: TCP send-buffer ceiling %d -> %d bytes (%s, hosted RAM %lu MiB, on-demand, tcp_mem-governed)\n",
		  old_max, target_max, policy, ram_mib);
	pr_notice("tcpcc: TCP memory policy ram_pages=%lu tcp_mem=%ld/%ld/%ld tcp_wmem=%d/%d/%d pressure=%lu\n",
		  ram_pages, READ_ONCE(sysctl_tcp_mem[0]), READ_ONCE(sysctl_tcp_mem[1]),
		  READ_ONCE(sysctl_tcp_mem[2]),
		  READ_ONCE(init_net.ipv4.sysctl_tcp_wmem[0]),
		  READ_ONCE(init_net.ipv4.sysctl_tcp_wmem[1]),
		  READ_ONCE(init_net.ipv4.sysctl_tcp_wmem[2]),
		  READ_ONCE(tcp_memory_pressure));
	tcpcc_compat_start_memory_telemetry();
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

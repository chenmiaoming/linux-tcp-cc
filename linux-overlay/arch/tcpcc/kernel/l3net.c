// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/if_arp.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/irq.h>
#include <linux/kthread.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <net/checksum.h>
#include <net/ip_tunnels.h>
#include <asm/host.h>
#include <asm/l3net.h>
#include <asm/tcpcc_compat.h>
#include <asm/tcpcc_control_abi.h>

#define TCPCC_L3_IRQ              3
#define TCPCC_L3_MTU              1500U
#define TCPCC_L3_MIN_MTU          68U
#define TCPCC_L3_TX_QUEUE_LIMIT   64U
#define TCPCC_L3_TX_LOW_WATERMARK 32U
#define TCPCC_L3_RX_BUFFER_SIZE   65535U
#define TCPCC_L3_IO_BUDGET        64U
#define TCPCC_L3_MIN_TEST_PACKETS 33U
#define TCPCC_HOST_EAGAIN         11

#define TCPCC_L3_EVENT_RX_READY    0
#define TCPCC_L3_EVENT_TX_WRITABLE 1

struct tcpcc_l3_runtime_stats {
	u64 io_rounds;
	u64 empty_rounds;
	u64 rx_irq_events;
	u64 tx_queue_wakeups;
	u64 tx_writable_events;
	u64 tx_eagain;
	u64 writable_arms;
	u64 rx_budget_yields;
	u64 tx_budget_yields;
};

struct tcpcc_l3_priv {
	struct net_device *dev;
	struct sk_buff_head tx_queue;
	struct sk_buff *tx_pending;
	wait_queue_head_t io_wait;
	struct task_struct *io_task;
	spinlock_t stats_lock;
	struct tcpcc_l3_stats stats;
	struct tcpcc_l3_runtime_stats runtime_stats;
	unsigned long pending_events;
	int host_fd;
	bool tx_blocked;
	bool shutting_down;
	bool event_registered;
	bool irq_registered;
};

static struct net_device *tcpcc_l3_dev;
static u8 tcpcc_l3_rx_buffer[TCPCC_L3_RX_BUFFER_SIZE];

static void tcpcc_l3_irq_noop(struct irq_data *data)
{
}

static struct irq_chip tcpcc_l3_irq_chip = {
	.name = "tcpcc-l3",
	.irq_ack = tcpcc_l3_irq_noop,
	.irq_mask = tcpcc_l3_irq_noop,
	.irq_unmask = tcpcc_l3_irq_noop,
};

static void tcpcc_l3_stats_rx(struct tcpcc_l3_priv *priv, size_t len)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->stats_lock, flags);
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += len;
	spin_unlock_irqrestore(&priv->stats_lock, flags);
}

static void tcpcc_l3_stats_rx_drop(struct tcpcc_l3_priv *priv, bool error)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->stats_lock, flags);
	priv->stats.rx_dropped++;
	if (error)
		priv->stats.rx_errors++;
	spin_unlock_irqrestore(&priv->stats_lock, flags);
}

static void tcpcc_l3_stats_tx(struct tcpcc_l3_priv *priv, size_t len)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->stats_lock, flags);
	priv->stats.tx_packets++;
	priv->stats.tx_bytes += len;
	spin_unlock_irqrestore(&priv->stats_lock, flags);
}

static void tcpcc_l3_stats_tx_drop(struct tcpcc_l3_priv *priv, bool error)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->stats_lock, flags);
	priv->stats.tx_dropped++;
	if (error)
		priv->stats.tx_errors++;
	spin_unlock_irqrestore(&priv->stats_lock, flags);
}

static bool tcpcc_l3_valid_ipv4(const u8 *packet, size_t len)
{
	const struct iphdr *iph;
	unsigned int header_len;
	unsigned int total_len;

	if (len < sizeof(struct iphdr))
		return false;

	iph = (const struct iphdr *)packet;
	if (iph->version != 4 || iph->ihl < 5)
		return false;

	header_len = iph->ihl * 4U;
	if (header_len > len)
		return false;

	total_len = ntohs(iph->tot_len);
	if (total_len != len || total_len < header_len)
		return false;

	if (ip_fast_csum((const u8 *)iph, iph->ihl))
		return false;

	return true;
}

static bool tcpcc_l3_valid_ipv6(const u8 *packet, size_t len)
{
	const struct ipv6hdr *ip6h;

	if (len < sizeof(struct ipv6hdr))
		return false;

	ip6h = (const struct ipv6hdr *)packet;
	if (ip6h->version != 6)
		return false;

	/* The 1500-byte hosted MTU cannot carry IPv6 jumbograms. */
	return ntohs(ip6h->payload_len) == len - sizeof(*ip6h);
}

static int tcpcc_l3_inject_one(struct tcpcc_l3_priv *priv,
			       const u8 *packet, size_t len)
{
	struct sk_buff *skb;
	__be16 protocol;

	if (len > priv->dev->mtu) {
		tcpcc_l3_stats_rx_drop(priv, false);
		return -EMSGSIZE;
	}
	if (len && (packet[0] >> 4) == 4 &&
	    tcpcc_l3_valid_ipv4(packet, len))
		protocol = htons(ETH_P_IP);
	else if (len && (packet[0] >> 4) == 6 &&
		 tcpcc_l3_valid_ipv6(packet, len))
		protocol = htons(ETH_P_IPV6);
	else {
		tcpcc_l3_stats_rx_drop(priv, true);
		return -EINVAL;
	}

	skb = netdev_alloc_skb_ip_align(priv->dev, len);
	if (!skb) {
		tcpcc_l3_stats_rx_drop(priv, true);
		return -ENOMEM;
	}

	skb_put_data(skb, packet, len);
	skb->dev = priv->dev;
	skb->protocol = protocol;
	skb->pkt_type = PACKET_HOST;
	skb->ip_summed = CHECKSUM_NONE;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	tcpcc_l3_stats_rx(priv, len);
	netif_rx(skb);
	return 0;
}

static bool tcpcc_l3_drain_rx(struct tcpcc_l3_priv *priv)
{
	unsigned int packets;

	for (packets = 0; packets < TCPCC_L3_IO_BUDGET; packets++) {
		ssize_t ret;

		ret = tcpcc_host_read_fd(priv->host_fd, tcpcc_l3_rx_buffer,
					 TCPCC_L3_RX_BUFFER_SIZE);
		if (ret == -TCPCC_HOST_EAGAIN)
			return false;
		if (ret < 0) {
			tcpcc_l3_stats_rx_drop(priv, true);
			return false;
		}
		if (!ret) {
			tcpcc_l3_stats_rx_drop(priv, true);
			return false;
		}

		(void)tcpcc_l3_inject_one(priv, tcpcc_l3_rx_buffer,
					  (size_t)ret);
	}

	priv->runtime_stats.rx_budget_yields++;
	return true;
}

static void tcpcc_l3_finish_tx(struct tcpcc_l3_priv *priv, ssize_t ret)
{
	struct sk_buff *skb = priv->tx_pending;

	if (!skb)
		return;
	if (ret == skb->len)
		tcpcc_l3_stats_tx(priv, skb->len);
	else
		tcpcc_l3_stats_tx_drop(priv, true);
	dev_kfree_skb(skb);
	priv->tx_pending = NULL;

	if (!READ_ONCE(priv->shutting_down) &&
	    netif_queue_stopped(priv->dev) &&
	    skb_queue_len(&priv->tx_queue) < TCPCC_L3_TX_LOW_WATERMARK)
		netif_wake_queue(priv->dev);
}

static bool tcpcc_l3_tx_ready(const struct tcpcc_l3_priv *priv)
{
	if (priv->tx_blocked)
		return test_bit(TCPCC_L3_EVENT_TX_WRITABLE,
				&priv->pending_events);
	return priv->tx_pending || !skb_queue_empty(&priv->tx_queue);
}

static bool tcpcc_l3_has_work(const struct tcpcc_l3_priv *priv)
{
	return kthread_should_stop() || READ_ONCE(priv->shutting_down) ||
	       test_bit(TCPCC_L3_EVENT_RX_READY, &priv->pending_events) ||
	       tcpcc_l3_tx_ready(priv);
}

static void tcpcc_l3_arm_writable(struct tcpcc_l3_priv *priv)
{
	int ret;

	/* EPOLLOUT is subscribed only while a write is actually blocked. */
	clear_bit(TCPCC_L3_EVENT_TX_WRITABLE, &priv->pending_events);
	ret = tcpcc_host_event_mod_mask(
		priv->host_fd, TCPCC_HOST_EVENT_IRQ_BASE + TCPCC_L3_IRQ,
		TCPCC_HOST_EVENT_READABLE | TCPCC_HOST_EVENT_WRITABLE, true);
	if (ret) {
		tcpcc_l3_finish_tx(priv, ret);
		return;
	}
	priv->tx_blocked = true;
	priv->runtime_stats.writable_arms++;
}

static void tcpcc_l3_drain_tx(struct tcpcc_l3_priv *priv)
{
	unsigned int packets;

	if (priv->tx_blocked) {
		int ret;

		if (!test_and_clear_bit(TCPCC_L3_EVENT_TX_WRITABLE,
					&priv->pending_events))
			return;
		ret = tcpcc_host_event_mod_mask(
			priv->host_fd,
			TCPCC_HOST_EVENT_IRQ_BASE + TCPCC_L3_IRQ,
			TCPCC_HOST_EVENT_READABLE, true);
		priv->tx_blocked = false;
		if (ret) {
			tcpcc_l3_finish_tx(priv, ret);
			return;
		}
	}

	for (packets = 0; packets < TCPCC_L3_IO_BUDGET; packets++) {
		ssize_t ret;

		if (!priv->tx_pending)
			priv->tx_pending = skb_dequeue(&priv->tx_queue);
		if (!priv->tx_pending)
			return;

		ret = tcpcc_host_write_fd(priv->host_fd,
					  priv->tx_pending->data,
					  priv->tx_pending->len);
		if (ret == -TCPCC_HOST_EAGAIN) {
			priv->runtime_stats.tx_eagain++;
			tcpcc_l3_arm_writable(priv);
			return;
		}
		tcpcc_l3_finish_tx(priv, ret);
	}

	if (priv->tx_pending || !skb_queue_empty(&priv->tx_queue))
		priv->runtime_stats.tx_budget_yields++;
}

static int tcpcc_l3_io_thread(void *arg)
{
	struct tcpcc_l3_priv *priv = arg;

	for (;;) {
		bool did_work = false;

		wait_event(priv->io_wait, tcpcc_l3_has_work(priv));
		if (kthread_should_stop() || READ_ONCE(priv->shutting_down))
			break;

		priv->runtime_stats.io_rounds++;
		if (test_and_clear_bit(TCPCC_L3_EVENT_RX_READY,
					&priv->pending_events)) {
			if (tcpcc_l3_drain_rx(priv))
				set_bit(TCPCC_L3_EVENT_RX_READY,
					&priv->pending_events);
			did_work = true;
		}
		if (tcpcc_l3_tx_ready(priv)) {
			tcpcc_l3_drain_tx(priv);
			did_work = true;
		}
		if (!did_work)
			priv->runtime_stats.empty_rounds++;
		cond_resched();
	}

	if (priv->tx_pending)
		tcpcc_l3_finish_tx(priv, -ECANCELED);
	return 0;
}

static irqreturn_t tcpcc_l3_irq_handler(int irq, void *dev_id)
{
	struct tcpcc_l3_priv *priv = dev_id;
	u32 events;

	if (!in_hardirq())
		return IRQ_NONE;
	events = tcpcc_host_irq_events(irq);
	if (events & (TCPCC_HOST_EVENT_READABLE |
		      TCPCC_HOST_EVENT_HANGUP | TCPCC_HOST_EVENT_ERROR)) {
		set_bit(TCPCC_L3_EVENT_RX_READY, &priv->pending_events);
		priv->runtime_stats.rx_irq_events++;
	}
	if (events & (TCPCC_HOST_EVENT_WRITABLE |
		      TCPCC_HOST_EVENT_HANGUP | TCPCC_HOST_EVENT_ERROR)) {
		set_bit(TCPCC_L3_EVENT_TX_WRITABLE, &priv->pending_events);
		priv->runtime_stats.tx_writable_events++;
	}
	wake_up(&priv->io_wait);
	return IRQ_HANDLED;
}

static int tcpcc_l3_open(struct net_device *dev)
{
	netif_carrier_on(dev);
	netif_start_queue(dev);
	return 0;
}

static int tcpcc_l3_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	netif_carrier_off(dev);
	return 0;
}

static netdev_tx_t tcpcc_l3_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct tcpcc_l3_priv *priv = netdev_priv(dev);
	bool wake_io;

	if (unlikely(skb->len > dev->mtu || skb->len < sizeof(struct iphdr))) {
		tcpcc_l3_stats_tx_drop(priv, false);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	if (unlikely(skb_linearize(skb))) {
		tcpcc_l3_stats_tx_drop(priv, true);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	spin_lock(&priv->tx_queue.lock);
	if (priv->tx_queue.qlen >= TCPCC_L3_TX_QUEUE_LIMIT) {
		netif_stop_queue(dev);
		spin_unlock(&priv->tx_queue.lock);
		return NETDEV_TX_BUSY;
	}
	wake_io = !priv->tx_queue.qlen;
	__skb_queue_tail(&priv->tx_queue, skb);
	if (priv->tx_queue.qlen >= TCPCC_L3_TX_QUEUE_LIMIT)
		netif_stop_queue(dev);
	spin_unlock(&priv->tx_queue.lock);

	if (wake_io) {
		priv->runtime_stats.tx_queue_wakeups++;
		wake_up(&priv->io_wait);
	}
	return NETDEV_TX_OK;
}

static void tcpcc_l3_get_stats64(struct net_device *dev,
				 struct rtnl_link_stats64 *stats)
{
	struct tcpcc_l3_priv *priv = netdev_priv(dev);
	struct tcpcc_l3_stats snapshot;
	unsigned long flags;

	spin_lock_irqsave(&priv->stats_lock, flags);
	snapshot = priv->stats;
	spin_unlock_irqrestore(&priv->stats_lock, flags);

	stats->rx_packets = snapshot.rx_packets;
	stats->rx_bytes = snapshot.rx_bytes;
	stats->rx_dropped = snapshot.rx_dropped;
	stats->rx_errors = snapshot.rx_errors;
	stats->tx_packets = snapshot.tx_packets;
	stats->tx_bytes = snapshot.tx_bytes;
	stats->tx_dropped = snapshot.tx_dropped;
	stats->tx_errors = snapshot.tx_errors;
}

static const struct net_device_ops tcpcc_l3_netdev_ops = {
	.ndo_open = tcpcc_l3_open,
	.ndo_stop = tcpcc_l3_stop,
	.ndo_start_xmit = tcpcc_l3_xmit,
	.ndo_get_stats64 = tcpcc_l3_get_stats64,
};

static void tcpcc_l3_setup(struct net_device *dev)
{
	struct tcpcc_l3_priv *priv = netdev_priv(dev);

	dev->netdev_ops = &tcpcc_l3_netdev_ops;
	dev->header_ops = &ip_tunnel_header_ops;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = TCPCC_L3_MTU;
	dev->min_mtu = TCPCC_L3_MIN_MTU;
	dev->max_mtu = TCPCC_L3_MTU;
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
	dev->tx_queue_len = TCPCC_L3_TX_QUEUE_LIMIT;

	priv->dev = dev;
	priv->host_fd = -1;
	skb_queue_head_init(&priv->tx_queue);
	init_waitqueue_head(&priv->io_wait);
	spin_lock_init(&priv->stats_lock);
}

static int tcpcc_l3_attach_config(
			int host_fd,
			const struct tcpcc_control_l3_config *config,
			int *ifindex)
{
	struct tcpcc_l3_priv *priv;
	struct net_device *dev;
	struct in6_addr ipv6_addr;
	u32 ipv4_addr = 0;
	int ret;

	if (tcpcc_l3_dev)
		return -EBUSY;
	if (host_fd < 3 || !config || !ifindex ||
	    memchr_inv(config->address.reserved, 0,
		       sizeof(config->address.reserved)) ||
	    memchr_inv(config->reserved, 0, sizeof(config->reserved)))
		return -EINVAL;
	if (config->address.version == TCPCC_CONTROL_IP_VERSION_4) {
		__be32 network_address;

		if (!config->prefix_len || config->prefix_len > 32 ||
		    memchr_inv(config->address.bytes + sizeof(network_address), 0,
			       sizeof(config->address.bytes) -
			       sizeof(network_address)))
			return -EINVAL;
		memcpy(&network_address, config->address.bytes,
		       sizeof(network_address));
		ipv4_addr = ntohl(network_address);
	} else if (config->address.version == TCPCC_CONTROL_IP_VERSION_6) {
		memcpy(&ipv6_addr, config->address.bytes, sizeof(ipv6_addr));
		if (!config->prefix_len || config->prefix_len > 128 ||
		    ipv6_addr_any(&ipv6_addr) ||
		    ipv6_addr_is_multicast(&ipv6_addr))
			return -EINVAL;
	} else {
		return -EAFNOSUPPORT;
	}

	/* No public socket exists yet; establish its lazy autotuning ceiling. */
	tcpcc_compat_configure_tcp_wmem();

	ret = tcpcc_host_set_nonblock(host_fd);
	if (ret)
		return ret;

	dev = alloc_netdev(sizeof(struct tcpcc_l3_priv), "tcpcc%d",
			   NET_NAME_ENUM, tcpcc_l3_setup);
	if (!dev)
		return -ENOMEM;

	priv = netdev_priv(dev);
	priv->host_fd = host_fd;

	ret = register_netdev(dev);
	if (ret)
		goto err_free;
	tcpcc_l3_dev = dev;

	irq_set_chip_and_handler(TCPCC_L3_IRQ, &tcpcc_l3_irq_chip,
				 handle_simple_irq);
	irq_clear_status_flags(TCPCC_L3_IRQ, IRQ_NOREQUEST | IRQ_NOPROBE);
	ret = request_irq(TCPCC_L3_IRQ, tcpcc_l3_irq_handler, IRQF_NO_THREAD,
			  "tcpcc-m5.1-l3", priv);
	if (ret)
		goto err_teardown;
	priv->irq_registered = true;

	ret = tcpcc_host_event_add_edge(host_fd,
					TCPCC_HOST_EVENT_IRQ_BASE + TCPCC_L3_IRQ);
	if (ret)
		goto err_teardown;
	priv->event_registered = true;

	priv->io_task = kthread_run(tcpcc_l3_io_thread, priv, "tcpcc-l3-io");
	if (IS_ERR(priv->io_task)) {
		ret = PTR_ERR(priv->io_task);
		priv->io_task = NULL;
		goto err_teardown;
	}

	if (config->address.version == TCPCC_CONTROL_IP_VERSION_4) {
		ret = tcpcc_compat_configure_ipv4(dev, ipv4_addr,
						  config->prefix_len);
		if (!ret)
			ret = tcpcc_compat_add_default_route_ipv4(dev,
							      ipv4_addr);
	} else {
		ret = tcpcc_compat_configure_ipv6(dev, &ipv6_addr,
						  config->prefix_len);
		if (!ret)
			ret = tcpcc_compat_add_default_route_ipv6(dev,
								  &ipv6_addr);
	}
	if (ret)
		goto err_teardown;

	ret = tcpcc_compat_validate_fq_qdisc(dev);
	if (ret)
		goto err_teardown;

	*ifindex = dev->ifindex;
	pr_notice("tcpcc: M11 L3 netdevice %s attached to host fd %d, mtu %u, "
		  "single budgeted event pump\n",
		  dev->name, host_fd, dev->mtu);
	return 0;

err_teardown:
	tcpcc_l3_teardown();
	return ret;
err_free:
	free_netdev(dev);
	return ret;
}

int tcpcc_l3_attach(int host_fd, u32 ipv4_addr, u32 prefix_len, int *ifindex)
{
	struct tcpcc_control_l3_config config = {
		.address.version = TCPCC_CONTROL_IP_VERSION_4,
		.prefix_len = prefix_len,
	};
	__be32 network_address = htonl(ipv4_addr);

	if (!prefix_len || prefix_len > 32)
		return -EINVAL;
	memcpy(config.address.bytes, &network_address, sizeof(network_address));
	return tcpcc_l3_attach_config(host_fd, &config, ifindex);
}

int tcpcc_l3_attach_ip(int host_fd,
		       const struct tcpcc_control_l3_config *config,
		       int *ifindex)
{
	return tcpcc_l3_attach_config(host_fd, config, ifindex);
}

int tcpcc_l3_get_stats(struct tcpcc_l3_stats *stats)
{
	struct tcpcc_l3_priv *priv;
	unsigned long flags;

	if (!tcpcc_l3_dev || !stats)
		return -ENODEV;

	priv = netdev_priv(tcpcc_l3_dev);
	spin_lock_irqsave(&priv->stats_lock, flags);
	*stats = priv->stats;
	spin_unlock_irqrestore(&priv->stats_lock, flags);
	return 0;
}

int tcpcc_l3_validate(void)
{
	struct tcpcc_l3_stats stats;
	int ret;

	ret = tcpcc_l3_get_stats(&stats);
	if (ret)
		return ret;
	if (stats.rx_packets < TCPCC_L3_MIN_TEST_PACKETS ||
	    stats.tx_packets < TCPCC_L3_MIN_TEST_PACKETS)
		return -ENODATA;
	if (!stats.rx_dropped)
		return -ENODATA;
	if (stats.rx_errors || stats.tx_errors)
		return -EIO;
	return 0;
}

void tcpcc_l3_teardown(void)
{
	struct tcpcc_l3_priv *priv;
	struct sk_buff *skb;
	struct net_device *dev = tcpcc_l3_dev;

	if (!dev)
		return;
	priv = netdev_priv(dev);
	WRITE_ONCE(priv->shutting_down, true);

	if (priv->event_registered) {
		(void)tcpcc_host_event_del(priv->host_fd);
		priv->event_registered = false;
	}
	if (priv->irq_registered) {
		disable_irq(TCPCC_L3_IRQ);
		free_irq(TCPCC_L3_IRQ, priv);
		priv->irq_registered = false;
	}

	netif_stop_queue(dev);
	if (priv->io_task) {
		wake_up(&priv->io_wait);
		kthread_stop(priv->io_task);
		priv->io_task = NULL;
	}

	while ((skb = skb_dequeue(&priv->tx_queue)) != NULL) {
		tcpcc_l3_stats_tx_drop(priv, false);
		dev_kfree_skb(skb);
	}

	pr_notice("tcpcc: M11 L3 pump rx_packets=%llu tx_packets=%llu "
		  "tx_dropped=%llu "
		  "rounds=%llu empty=%llu rx_irq=%llu "
		  "tx_wake=%llu writable_irq=%llu eagain=%llu arms=%llu "
		  "rx_budget=%llu tx_budget=%llu\n",
		  priv->stats.rx_packets,
		  priv->stats.tx_packets,
		  priv->stats.tx_dropped,
		  priv->runtime_stats.io_rounds,
		  priv->runtime_stats.empty_rounds,
		  priv->runtime_stats.rx_irq_events,
		  priv->runtime_stats.tx_queue_wakeups,
		  priv->runtime_stats.tx_writable_events,
		  priv->runtime_stats.tx_eagain,
		  priv->runtime_stats.writable_arms,
		  priv->runtime_stats.rx_budget_yields,
		  priv->runtime_stats.tx_budget_yields);

	unregister_netdev(dev);
	if (priv->host_fd >= 0)
		(void)tcpcc_host_close(priv->host_fd);
	tcpcc_l3_dev = NULL;
	free_netdev(dev);
}

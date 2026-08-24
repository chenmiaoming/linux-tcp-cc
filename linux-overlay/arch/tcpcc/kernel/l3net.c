// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/errno.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/irq.h>
#include <linux/kthread.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/sockios.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <net/checksum.h>
#include <net/ip_tunnels.h>
#include <net/net_namespace.h>
#include <asm/host.h>
#include <asm/l3net.h>

#define TCPCC_L3_IRQ              3
#define TCPCC_L3_MTU              1500U
#define TCPCC_L3_MIN_MTU          68U
#define TCPCC_L3_TX_QUEUE_LIMIT   64U
#define TCPCC_L3_TX_LOW_WATERMARK 32U
#define TCPCC_L3_RX_BUFFER_SIZE   65535U
#define TCPCC_L3_MIN_TEST_PACKETS 33U
#define TCPCC_HOST_EAGAIN         11

struct tcpcc_l3_priv {
	struct net_device *dev;
	struct sk_buff_head tx_queue;
	struct completion rx_ready;
	struct completion tx_ready;
	struct task_struct *rx_task;
	struct task_struct *tx_task;
	spinlock_t stats_lock;
	struct tcpcc_l3_stats stats;
	int host_fd;
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

static int tcpcc_l3_inject_one(struct tcpcc_l3_priv *priv,
			       const u8 *packet, size_t len)
{
	struct sk_buff *skb;

	if (len > priv->dev->mtu) {
		tcpcc_l3_stats_rx_drop(priv, false);
		return -EMSGSIZE;
	}
	if (!tcpcc_l3_valid_ipv4(packet, len)) {
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
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_HOST;
	skb->ip_summed = CHECKSUM_NONE;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	tcpcc_l3_stats_rx(priv, len);
	netif_rx(skb);
	return 0;
}

static int tcpcc_l3_rx_thread(void *arg)
{
	struct tcpcc_l3_priv *priv = arg;

	for (;;) {
		wait_for_completion(&priv->rx_ready);
		if (kthread_should_stop())
			break;

		for (;;) {
			ssize_t ret;

			ret = tcpcc_host_read_fd(priv->host_fd, tcpcc_l3_rx_buffer,
						 TCPCC_L3_RX_BUFFER_SIZE);
			if (ret == -TCPCC_HOST_EAGAIN)
				break;
			if (ret < 0) {
				tcpcc_l3_stats_rx_drop(priv, true);
				break;
			}
			if (!ret) {
				tcpcc_l3_stats_rx_drop(priv, true);
				break;
			}

			(void)tcpcc_l3_inject_one(priv, tcpcc_l3_rx_buffer,
						  (size_t)ret);
		}
	}

	return 0;
}

static int tcpcc_l3_tx_thread(void *arg)
{
	struct tcpcc_l3_priv *priv = arg;

	for (;;) {
		struct sk_buff *skb;

		wait_for_completion(&priv->tx_ready);
		if (kthread_should_stop())
			break;

		while ((skb = skb_dequeue(&priv->tx_queue)) != NULL) {
			ssize_t ret;

			for (;;) {
				ret = tcpcc_host_write_fd(priv->host_fd, skb->data,
							  skb->len);
				if (ret != -TCPCC_HOST_EAGAIN)
					break;
				if (kthread_should_stop())
					break;
				schedule_timeout_uninterruptible(1);
			}

			if (ret == skb->len)
				tcpcc_l3_stats_tx(priv, skb->len);
			else
				tcpcc_l3_stats_tx_drop(priv, true);
			dev_kfree_skb(skb);

			if (netif_queue_stopped(priv->dev) &&
			    skb_queue_len(&priv->tx_queue) <
					TCPCC_L3_TX_LOW_WATERMARK)
				netif_wake_queue(priv->dev);

			if (kthread_should_stop())
				break;
		}
	}

	return 0;
}

static irqreturn_t tcpcc_l3_irq_handler(int irq, void *dev_id)
{
	struct tcpcc_l3_priv *priv = dev_id;

	if (!in_hardirq())
		return IRQ_NONE;
	complete(&priv->rx_ready);
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
	__skb_queue_tail(&priv->tx_queue, skb);
	if (priv->tx_queue.qlen >= TCPCC_L3_TX_QUEUE_LIMIT)
		netif_stop_queue(dev);
	spin_unlock(&priv->tx_queue.lock);

	complete(&priv->tx_ready);
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
	init_completion(&priv->rx_ready);
	init_completion(&priv->tx_ready);
	spin_lock_init(&priv->stats_lock);
}

static int tcpcc_l3_configure_ipv4(struct net_device *dev, u32 address,
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

int tcpcc_l3_attach(int host_fd, u32 ipv4_addr, u32 prefix_len, int *ifindex)
{
	struct tcpcc_l3_priv *priv;
	struct net_device *dev;
	int ret;

	if (tcpcc_l3_dev)
		return -EBUSY;
	if (host_fd < 3 || !ifindex)
		return -EINVAL;

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

	priv->rx_task = kthread_run(tcpcc_l3_rx_thread, priv, "tcpcc-l3-rx");
	if (IS_ERR(priv->rx_task)) {
		ret = PTR_ERR(priv->rx_task);
		priv->rx_task = NULL;
		goto err_teardown;
	}

	priv->tx_task = kthread_run(tcpcc_l3_tx_thread, priv, "tcpcc-l3-tx");
	if (IS_ERR(priv->tx_task)) {
		ret = PTR_ERR(priv->tx_task);
		priv->tx_task = NULL;
		goto err_teardown;
	}

	ret = tcpcc_l3_configure_ipv4(dev, ipv4_addr, prefix_len);
	if (ret)
		goto err_teardown;

	*ifindex = dev->ifindex;
	pr_notice("tcpcc: M5.1 L3 netdevice %s attached to host fd %d, mtu %u\n",
		  dev->name, host_fd, dev->mtu);
	return 0;

err_teardown:
	tcpcc_l3_teardown();
	return ret;
err_free:
	free_netdev(dev);
	return ret;
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
	if (priv->rx_task) {
		complete(&priv->rx_ready);
		kthread_stop(priv->rx_task);
		priv->rx_task = NULL;
	}
	if (priv->tx_task) {
		complete(&priv->tx_ready);
		kthread_stop(priv->tx_task);
		priv->tx_task = NULL;
	}

	while ((skb = skb_dequeue(&priv->tx_queue)) != NULL) {
		tcpcc_l3_stats_tx_drop(priv, false);
		dev_kfree_skb(skb);
	}

	unregister_netdev(dev);
	if (priv->host_fd >= 0)
		(void)tcpcc_host_close(priv->host_fd);
	tcpcc_l3_dev = NULL;
	free_netdev(dev);
}

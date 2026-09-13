// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/panic.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <net/net_namespace.h>

#include <asm/tcpcc_compat.h>

#define TCPCC_LOOPBACK_TEST_ROUNDS  16
#define TCPCC_LOOPBACK_PAYLOAD_SIZE (64U * 1024U)
#define TCPCC_LOOPBACK_BACKLOG      8

struct tcpcc_loopback_buffers {
	u8 *tx;
	u8 *server_rx;
	u8 *client_rx;
};

struct tcpcc_loopback_client_ctx {
	struct completion done;
	struct tcpcc_loopback_buffers *buffers;
	__be16 port;
	unsigned int round;
	int result;
};

static u8 *tcpcc_loopback_alloc_buffer(void)
{
	return (u8 *)__get_free_pages(GFP_KERNEL,
				      get_order(TCPCC_LOOPBACK_PAYLOAD_SIZE));
}

static void tcpcc_loopback_free_buffer(u8 *buffer)
{
	if (buffer)
		free_pages((unsigned long)buffer,
			   get_order(TCPCC_LOOPBACK_PAYLOAD_SIZE));
}

static int tcpcc_loopback_alloc_buffers(struct tcpcc_loopback_buffers *buffers)
{
	buffers->tx = tcpcc_loopback_alloc_buffer();
	buffers->server_rx = tcpcc_loopback_alloc_buffer();
	buffers->client_rx = tcpcc_loopback_alloc_buffer();
	if (buffers->tx && buffers->server_rx && buffers->client_rx)
		return 0;

	tcpcc_loopback_free_buffer(buffers->client_rx);
	tcpcc_loopback_free_buffer(buffers->server_rx);
	tcpcc_loopback_free_buffer(buffers->tx);
	memset(buffers, 0, sizeof(*buffers));
	return -ENOMEM;
}

static void tcpcc_loopback_free_buffers(struct tcpcc_loopback_buffers *buffers)
{
	tcpcc_loopback_free_buffer(buffers->client_rx);
	tcpcc_loopback_free_buffer(buffers->server_rx);
	tcpcc_loopback_free_buffer(buffers->tx);
	memset(buffers, 0, sizeof(*buffers));
}

static void tcpcc_loopback_fill_payload(u8 *buffer, unsigned int round)
{
	unsigned int i;

	for (i = 0; i < TCPCC_LOOPBACK_PAYLOAD_SIZE; i++)
		buffer[i] = (u8)((i * 131U + round * 17U) & 0xffU);
}

static int tcpcc_loopback_send_all(struct socket *sock, const u8 *buf,
				    size_t len)
{
	size_t done = 0;

	while (done < len) {
		struct msghdr msg = { };
		struct kvec vec = {
			.iov_base = (void *)(buf + done),
			.iov_len = len - done,
		};
		int ret;

		ret = kernel_sendmsg(sock, &msg, &vec, 1, len - done);
		if (ret < 0)
			return ret;
		if (!ret)
			return -EIO;
		done += ret;
	}

	return 0;
}

static int tcpcc_loopback_recv_all(struct socket *sock, u8 *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		struct msghdr msg = { };
		struct kvec vec = {
			.iov_base = buf + done,
			.iov_len = len - done,
		};
		int ret;

		ret = kernel_recvmsg(sock, &msg, &vec, 1, len - done, 0);
		if (ret < 0)
			return ret;
		if (!ret)
			return -ECONNRESET;
		done += ret;
	}

	return 0;
}

static int tcpcc_loopback_client(void *arg)
{
	struct tcpcc_loopback_client_ctx *ctx = arg;
	struct tcpcc_loopback_buffers *buffers = ctx->buffers;
	struct sockaddr_in peer = {
		.sin_family = AF_INET,
		.sin_port = ctx->port,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct socket *sock = NULL;
	int ret;

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
			       &sock);
	if (ret)
		goto out;

	ret = tcpcc_compat_kernel_connect(sock, &peer, sizeof(peer), 0);
	if (ret)
		goto out_release;

	ret = tcpcc_loopback_send_all(sock, buffers->tx,
				      TCPCC_LOOPBACK_PAYLOAD_SIZE);
	if (ret)
		goto out_release;

	ret = tcpcc_loopback_recv_all(sock, buffers->client_rx,
				      TCPCC_LOOPBACK_PAYLOAD_SIZE);
	if (ret)
		goto out_release;

	if (memcmp(buffers->client_rx, buffers->tx,
		   TCPCC_LOOPBACK_PAYLOAD_SIZE)) {
		ret = -EBADMSG;
		goto out_release;
	}

out_release:
	if (sock) {
		kernel_sock_shutdown(sock, SHUT_RDWR);
		sock_release(sock);
	}
out:
	ctx->result = ret;
	complete(&ctx->done);

	/* Keep the task object joinable until the server reaps it. */
	while (!kthread_should_stop())
		schedule_timeout_uninterruptible(1);

	return ret;
}

static int tcpcc_loopback_bring_up(void)
{
	struct net_device *lo;
	int ret;

	rtnl_lock();
	lo = __dev_get_by_name(&init_net, "lo");
	if (!lo) {
		ret = -ENODEV;
		goto out_unlock;
	}

	ret = dev_open(lo, NULL);
	if (!ret && !(lo->flags & IFF_UP))
		ret = -ENETDOWN;

out_unlock:
	rtnl_unlock();
	return ret;
}

static int tcpcc_loopback_server_round(struct socket *listener, __be16 port,
					unsigned int round,
					struct tcpcc_loopback_buffers *buffers)
{
	struct tcpcc_loopback_client_ctx ctx;
	struct task_struct *client;
	struct socket *accepted = NULL;
	int client_ret;
	int ret;

	init_completion(&ctx.done);
	ctx.buffers = buffers;
	ctx.port = port;
	ctx.round = round;
	ctx.result = -EINPROGRESS;
	tcpcc_loopback_fill_payload(buffers->tx, round);
	memset(buffers->server_rx, 0, TCPCC_LOOPBACK_PAYLOAD_SIZE);
	memset(buffers->client_rx, 0, TCPCC_LOOPBACK_PAYLOAD_SIZE);

	client = kthread_run(tcpcc_loopback_client, &ctx,
			     "tcpcc-m4.1/%u", round);
	if (IS_ERR(client))
		return PTR_ERR(client);

	ret = kernel_accept(listener, &accepted, 0);
	if (ret)
		goto out_stop;

	ret = tcpcc_loopback_recv_all(accepted, buffers->server_rx,
				      TCPCC_LOOPBACK_PAYLOAD_SIZE);
	if (ret)
		goto out_release;

	if (memcmp(buffers->server_rx, buffers->tx,
		   TCPCC_LOOPBACK_PAYLOAD_SIZE)) {
		ret = -EBADMSG;
		goto out_release;
	}

	ret = tcpcc_loopback_send_all(accepted, buffers->server_rx,
				      TCPCC_LOOPBACK_PAYLOAD_SIZE);

out_release:
	if (accepted) {
		kernel_sock_shutdown(accepted, SHUT_RDWR);
		sock_release(accepted);
	}

	wait_for_completion(&ctx.done);
	if (!ret && ctx.result)
		ret = ctx.result;

out_stop:
	client_ret = kthread_stop(client);
	if (!ret && client_ret)
		ret = client_ret;
	return ret;
}

static int __init tcpcc_loopback_tcp_selftest(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct tcpcc_loopback_buffers buffers = { };
	struct socket *listener = NULL;
	unsigned int round;
	int ret;

	ret = tcpcc_loopback_bring_up();
	if (ret)
		panic("tcpcc: M4.1 failed to bring loopback up: %d", ret);

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
			       &listener);
	if (ret)
		panic("tcpcc: M4.1 listener socket creation failed: %d", ret);

	ret = tcpcc_compat_kernel_bind(listener, &addr, sizeof(addr));
	if (ret)
		panic("tcpcc: M4.1 loopback bind failed: %d", ret);

	ret = kernel_listen(listener, TCPCC_LOOPBACK_BACKLOG);
	if (ret)
		panic("tcpcc: M4.1 loopback listen failed: %d", ret);

	ret = kernel_getsockname(listener, (struct sockaddr *)&addr);
	if (ret < 0)
		panic("tcpcc: M4.1 getsockname failed: %d", ret);
	if (!addr.sin_port)
		panic("tcpcc: M4.1 listener received zero TCP port");

	ret = tcpcc_loopback_alloc_buffers(&buffers);
	if (ret)
		panic("tcpcc: M4.1 temporary buffer allocation failed: %d", ret);

	pr_notice("tcpcc: M4.1 loopback TCP stress starting (%u rounds x %u bytes each direction)\n",
		  TCPCC_LOOPBACK_TEST_ROUNDS, TCPCC_LOOPBACK_PAYLOAD_SIZE);

	for (round = 0; round < TCPCC_LOOPBACK_TEST_ROUNDS; round++) {
		ret = tcpcc_loopback_server_round(listener, addr.sin_port, round,
						  &buffers);
		if (ret)
			panic("tcpcc: M4.1 loopback TCP round %u failed: %d",
			      round, ret);
	}

	kernel_sock_shutdown(listener, SHUT_RDWR);
	sock_release(listener);
	tcpcc_loopback_free_buffers(&buffers);

	pr_notice("tcpcc: M4.1 loopback TCP stress passed (%u rounds, %u bytes each direction); %u KiB temporary buffers returned to guest RAM\n",
		  TCPCC_LOOPBACK_TEST_ROUNDS, TCPCC_LOOPBACK_PAYLOAD_SIZE,
		  (3U * TCPCC_LOOPBACK_PAYLOAD_SIZE) >> 10);
	return 0;
}
fs_initcall_sync(tcpcc_loopback_tcp_selftest);

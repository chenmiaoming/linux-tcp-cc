// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/panic.h>
#include <linux/sched.h>
#include <linux/sockptr.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <asm/host.h>
#include <asm/l3net.h>

#define TCPCC_CONTROL_IRQ          2
#define TCPCC_CONTROL_MAGIC        0x32434354U /* "TCC2" on x86-64 */
#define TCPCC_CONTROL_VERSION      1
#define TCPCC_CONTROL_MAX_SOCKETS  16
#define TCPCC_CONTROL_MAX_PAYLOAD  256

/*
 * M4.2/M5.1 control ABI.
 *
 * ARCH=tcpcc currently requires an x86-64 Linux host, so the fixed-width
 * fields below are intentionally native little-endian. Requests arrive on
 * host stdin and responses are written to host stdout. Host readiness only
 * raises a virtual IRQ; all socket and device-control work runs in a Linux
 * kthread and may sleep normally.
 */
enum tcpcc_control_op {
	TCPCC_CONTROL_SOCKET = 1,
	TCPCC_CONTROL_BIND,
	TCPCC_CONTROL_LISTEN,
	TCPCC_CONTROL_CONNECT,
	TCPCC_CONTROL_ACCEPT,
	TCPCC_CONTROL_WRITE,
	TCPCC_CONTROL_READ,
	TCPCC_CONTROL_CLOSE,
	TCPCC_CONTROL_SET_CC,
	TCPCC_CONTROL_GET_CC,
	TCPCC_CONTROL_FINISH,
	TCPCC_CONTROL_L3_ATTACH,
	TCPCC_CONTROL_L3_STATS,
};

struct tcpcc_control_request {
	u32 magic;
	u16 version;
	u16 op;
	s32 handle;
	u32 arg0;
	u32 arg1;
	u32 length;
	u8 data[TCPCC_CONTROL_MAX_PAYLOAD];
};

struct tcpcc_control_response {
	u32 magic;
	u16 version;
	u16 op;
	s32 status;
	s32 handle;
	u32 length;
	u8 data[TCPCC_CONTROL_MAX_PAYLOAD];
};

static struct socket *tcpcc_control_sockets[TCPCC_CONTROL_MAX_SOCKETS];
static struct completion tcpcc_control_request_ready;
static struct completion tcpcc_control_finished;
static struct task_struct *tcpcc_control_task;
static int tcpcc_control_result;

static void tcpcc_control_irq_noop(struct irq_data *data)
{
}

static struct irq_chip tcpcc_control_irq_chip = {
	.name = "tcpcc-control",
	.irq_ack = tcpcc_control_irq_noop,
	.irq_mask = tcpcc_control_irq_noop,
	.irq_unmask = tcpcc_control_irq_noop,
};

static int tcpcc_control_read_exact(void *buf, size_t len)
{
	u8 *cursor = buf;
	size_t done = 0;

	while (done < len) {
		ssize_t ret = tcpcc_host_read_fd(TCPCC_HOST_STDIN_FILENO,
						 cursor + done, len - done);

		/*
		 * Host fds must never provide Linux task sleeping semantics. stdin is
		 * nonblocking, so a stale readiness completion or a partial request
		 * returns EAGAIN here. Sleep on the Linux completion until epoll raises
		 * the next virtual IRQ instead of blocking the single host/vCPU thread
		 * inside a host read(2).
		 */
		if (ret == -EAGAIN) {
			wait_for_completion(&tcpcc_control_request_ready);
			if (kthread_should_stop())
				return -EINTR;
			continue;
		}
		if (ret < 0)
			return (int)ret;
		if (!ret)
			return -EPIPE;
		done += ret;
	}

	return 0;
}

static int tcpcc_control_write_exact(const void *buf, size_t len)
{
	const u8 *cursor = buf;
	size_t done = 0;

	while (done < len) {
		ssize_t ret = tcpcc_host_write_fd(TCPCC_HOST_STDOUT_FILENO,
						  cursor + done, len - done);

		if (ret < 0)
			return (int)ret;
		if (!ret)
			return -EPIPE;
		done += ret;
	}

	return 0;
}

static struct socket *tcpcc_control_lookup(s32 handle)
{
	if (handle < 1 || handle > TCPCC_CONTROL_MAX_SOCKETS)
		return NULL;
	return tcpcc_control_sockets[handle - 1];
}

static int tcpcc_control_install_socket(struct socket *sock)
{
	unsigned int i;

	for (i = 0; i < TCPCC_CONTROL_MAX_SOCKETS; i++) {
		if (!tcpcc_control_sockets[i]) {
			tcpcc_control_sockets[i] = sock;
			return i + 1;
		}
	}

	return -EMFILE;
}

static void tcpcc_control_release_handle(s32 handle)
{
	struct socket *sock = tcpcc_control_lookup(handle);

	if (!sock)
		return;

	kernel_sock_shutdown(sock, SHUT_RDWR);
	sock_release(sock);
	tcpcc_control_sockets[handle - 1] = NULL;
}

static void tcpcc_control_release_all(void)
{
	unsigned int i;

	for (i = 0; i < TCPCC_CONTROL_MAX_SOCKETS; i++) {
		if (tcpcc_control_sockets[i])
			tcpcc_control_release_handle(i + 1);
	}
}

static int tcpcc_control_socket(struct tcpcc_control_response *response)
{
	struct socket *sock;
	int handle;
	int ret;

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
			       &sock);
	if (ret)
		return ret;

	handle = tcpcc_control_install_socket(sock);
	if (handle < 0) {
		sock_release(sock);
		return handle;
	}

	response->handle = handle;
	return 0;
}

static int tcpcc_control_bind(const struct tcpcc_control_request *request)
{
	struct socket *sock = tcpcc_control_lookup(request->handle);
	struct sockaddr_in addr;

	if (!sock)
		return -EBADF;
	if (request->arg1 > 0xffffU)
		return -EINVAL;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(request->arg0);
	addr.sin_port = htons((u16)request->arg1);
	return kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
}

static int tcpcc_control_listen(const struct tcpcc_control_request *request)
{
	struct socket *sock = tcpcc_control_lookup(request->handle);

	if (!sock)
		return -EBADF;
	if (!request->arg0 || request->arg0 > SOMAXCONN)
		return -EINVAL;
	return kernel_listen(sock, request->arg0);
}

static int tcpcc_control_connect(const struct tcpcc_control_request *request)
{
	struct socket *sock = tcpcc_control_lookup(request->handle);
	struct sockaddr_in addr;

	if (!sock)
		return -EBADF;
	if (request->arg1 > 0xffffU)
		return -EINVAL;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(request->arg0);
	addr.sin_port = htons((u16)request->arg1);
	return kernel_connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
}

static int tcpcc_control_accept(const struct tcpcc_control_request *request,
				struct tcpcc_control_response *response)
{
	struct socket *listener = tcpcc_control_lookup(request->handle);
	struct socket *accepted;
	int handle;
	int ret;

	if (!listener)
		return -EBADF;

	ret = kernel_accept(listener, &accepted, 0);
	if (ret)
		return ret;

	handle = tcpcc_control_install_socket(accepted);
	if (handle < 0) {
		sock_release(accepted);
		return handle;
	}

	response->handle = handle;
	return 0;
}

static int tcpcc_control_send_all(struct socket *sock, const u8 *buf,
				  size_t len)
{
	size_t done = 0;

	while (done < len) {
		struct msghdr msg = { };
		struct kvec vec = {
			.iov_base = (void *)(buf + done),
			.iov_len = len - done,
		};
		int ret = kernel_sendmsg(sock, &msg, &vec, 1, len - done);

		if (ret < 0)
			return ret;
		if (!ret)
			return -EIO;
		done += ret;
	}

	return 0;
}

static int tcpcc_control_recv_all(struct socket *sock, u8 *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		struct msghdr msg = { };
		struct kvec vec = {
			.iov_base = buf + done,
			.iov_len = len - done,
		};
		int ret = kernel_recvmsg(sock, &msg, &vec, 1, len - done, 0);

		if (ret < 0)
			return ret;
		if (!ret)
			return -ECONNRESET;
		done += ret;
	}

	return 0;
}

static int tcpcc_control_write(const struct tcpcc_control_request *request,
			       struct tcpcc_control_response *response)
{
	struct socket *sock = tcpcc_control_lookup(request->handle);
	int ret;

	if (!sock)
		return -EBADF;
	if (!request->length || request->length > TCPCC_CONTROL_MAX_PAYLOAD)
		return -EMSGSIZE;

	ret = tcpcc_control_send_all(sock, request->data, request->length);
	if (!ret)
		response->length = request->length;
	return ret;
}

static int tcpcc_control_read(const struct tcpcc_control_request *request,
			      struct tcpcc_control_response *response)
{
	struct socket *sock = tcpcc_control_lookup(request->handle);
	int ret;

	if (!sock)
		return -EBADF;
	if (!request->arg0 || request->arg0 > TCPCC_CONTROL_MAX_PAYLOAD)
		return -EMSGSIZE;

	ret = tcpcc_control_recv_all(sock, response->data, request->arg0);
	if (!ret)
		response->length = request->arg0;
	return ret;
}

static int tcpcc_control_close(const struct tcpcc_control_request *request)
{
	if (!tcpcc_control_lookup(request->handle))
		return -EBADF;
	tcpcc_control_release_handle(request->handle);
	return 0;
}

static int tcpcc_control_set_cc(const struct tcpcc_control_request *request)
{
	struct socket *sock = tcpcc_control_lookup(request->handle);

	if (!sock)
		return -EBADF;
	if (!request->length || request->length >= TCP_CA_NAME_MAX)
		return -EINVAL;

	return do_tcp_setsockopt(sock->sk, SOL_TCP, TCP_CONGESTION,
				 KERNEL_SOCKPTR((void *)request->data),
				 request->length);
}

static int tcpcc_control_get_cc(const struct tcpcc_control_request *request,
			       struct tcpcc_control_response *response)
{
	struct socket *sock = tcpcc_control_lookup(request->handle);
	int len = TCP_CA_NAME_MAX;
	int ret;

	if (!sock)
		return -EBADF;

	ret = do_tcp_getsockopt(sock->sk, SOL_TCP, TCP_CONGESTION,
				KERNEL_SOCKPTR(response->data),
				KERNEL_SOCKPTR(&len));
	if (ret)
		return ret;

	response->length = strnlen(response->data,
				   min_t(unsigned int, len,
					 TCPCC_CONTROL_MAX_PAYLOAD));
	return 0;
}

static int tcpcc_control_l3_attach(const struct tcpcc_control_request *request,
				   struct tcpcc_control_response *response)
{
	int ifindex;
	int ret;

	ret = tcpcc_l3_attach(request->handle, request->arg0, request->arg1,
			      &ifindex);
	if (!ret)
		response->handle = ifindex;
	return ret;
}

static int tcpcc_control_l3_stats(struct tcpcc_control_response *response)
{
	struct tcpcc_l3_stats stats;
	int ret;

	BUILD_BUG_ON(sizeof(stats) > TCPCC_CONTROL_MAX_PAYLOAD);
	ret = tcpcc_l3_get_stats(&stats);
	if (ret)
		return ret;
	memcpy(response->data, &stats, sizeof(stats));
	response->length = sizeof(stats);
	return 0;
}

static int tcpcc_control_execute(const struct tcpcc_control_request *request,
				 struct tcpcc_control_response *response)
{
	switch (request->op) {
	case TCPCC_CONTROL_SOCKET:
		return tcpcc_control_socket(response);
	case TCPCC_CONTROL_BIND:
		return tcpcc_control_bind(request);
	case TCPCC_CONTROL_LISTEN:
		return tcpcc_control_listen(request);
	case TCPCC_CONTROL_CONNECT:
		return tcpcc_control_connect(request);
	case TCPCC_CONTROL_ACCEPT:
		return tcpcc_control_accept(request, response);
	case TCPCC_CONTROL_WRITE:
		return tcpcc_control_write(request, response);
	case TCPCC_CONTROL_READ:
		return tcpcc_control_read(request, response);
	case TCPCC_CONTROL_CLOSE:
		return tcpcc_control_close(request);
	case TCPCC_CONTROL_SET_CC:
		return tcpcc_control_set_cc(request);
	case TCPCC_CONTROL_GET_CC:
		return tcpcc_control_get_cc(request, response);
	case TCPCC_CONTROL_FINISH:
		return tcpcc_l3_validate();
	case TCPCC_CONTROL_L3_ATTACH:
		return tcpcc_control_l3_attach(request, response);
	case TCPCC_CONTROL_L3_STATS:
		return tcpcc_control_l3_stats(response);
	default:
		return -EOPNOTSUPP;
	}
}

static int tcpcc_control_thread(void *unused)
{
	for (;;) {
		struct tcpcc_control_request request;
		struct tcpcc_control_response response;
		int ret;

		wait_for_completion(&tcpcc_control_request_ready);
		if (kthread_should_stop())
			break;

		ret = tcpcc_control_read_exact(&request, sizeof(request));
		if (ret) {
			tcpcc_control_result = ret;
			complete(&tcpcc_control_finished);
			break;
		}

		memset(&response, 0, sizeof(response));
		response.magic = TCPCC_CONTROL_MAGIC;
		response.version = TCPCC_CONTROL_VERSION;
		response.op = request.op;
		response.handle = request.handle;

		if (request.magic != TCPCC_CONTROL_MAGIC ||
		    request.version != TCPCC_CONTROL_VERSION)
			ret = -EPROTO;
		else
			ret = tcpcc_control_execute(&request, &response);
		response.status = ret;

		ret = tcpcc_control_write_exact(&response, sizeof(response));
		if (ret) {
			tcpcc_control_result = ret;
			complete(&tcpcc_control_finished);
			break;
		}

		if (request.op == TCPCC_CONTROL_FINISH) {
			tcpcc_control_result = response.status;
			complete(&tcpcc_control_finished);
			break;
		}
	}

	/* Keep the task object joinable until the initcall reaps it. */
	while (!kthread_should_stop())
		schedule_timeout_uninterruptible(1);

	return tcpcc_control_result;
}

static irqreturn_t tcpcc_control_irq_handler(int irq, void *dev_id)
{
	if (!in_hardirq())
		panic("tcpcc: M4.2 control IRQ ran outside hardirq context");

	complete(&tcpcc_control_request_ready);
	return IRQ_HANDLED;
}

static int __init tcpcc_control_selftest(void)
{
	struct tcpcc_l3_stats l3_stats = { };
	int ret;

	init_completion(&tcpcc_control_request_ready);
	init_completion(&tcpcc_control_finished);
	tcpcc_control_result = -EINPROGRESS;

	irq_set_chip_and_handler(TCPCC_CONTROL_IRQ, &tcpcc_control_irq_chip,
				 handle_simple_irq);
	irq_clear_status_flags(TCPCC_CONTROL_IRQ, IRQ_NOREQUEST | IRQ_NOPROBE);

	ret = request_irq(TCPCC_CONTROL_IRQ, tcpcc_control_irq_handler,
			  IRQF_NO_THREAD, "tcpcc-m4.2-control", NULL);
	if (ret)
		panic("tcpcc: M4.2 request_irq failed: %d", ret);

	ret = tcpcc_host_set_nonblock(TCPCC_HOST_STDIN_FILENO);
	if (ret)
		panic("tcpcc: M4.2 stdin nonblocking setup failed: %d", ret);

	ret = tcpcc_host_event_add(TCPCC_HOST_STDIN_FILENO,
				   TCPCC_HOST_EVENT_IRQ_BASE + TCPCC_CONTROL_IRQ);
	if (ret)
		panic("tcpcc: M4.2 stdin event registration failed: %d", ret);

	tcpcc_control_task = kthread_run(tcpcc_control_thread, NULL,
					 "tcpcc-m4.2-control");
	if (IS_ERR(tcpcc_control_task))
		panic("tcpcc: M4.2 control kthread creation failed: %ld",
		      PTR_ERR(tcpcc_control_task));

	pr_notice("tcpcc: M4.2 host control bridge ready on stdin/stdout\n");
	wait_for_completion(&tcpcc_control_finished);

	ret = tcpcc_host_event_del(TCPCC_HOST_STDIN_FILENO);
	if (ret)
		panic("tcpcc: M4.2 stdin event removal failed: %d", ret);
	disable_irq(TCPCC_CONTROL_IRQ);
	free_irq(TCPCC_CONTROL_IRQ, NULL);

	ret = kthread_stop(tcpcc_control_task);
	if (!tcpcc_control_result && ret)
		tcpcc_control_result = ret;
	tcpcc_control_task = NULL;
	tcpcc_control_release_all();

	if (!tcpcc_control_result) {
		ret = tcpcc_l3_get_stats(&l3_stats);
		if (ret)
			tcpcc_control_result = ret;
	}

	tcpcc_l3_teardown();

	if (tcpcc_control_result)
		panic("tcpcc: M5.1 host control/L3 validation failed: %d",
		      tcpcc_control_result);

	pr_notice("tcpcc: M4.2 host control bridge passed native loopback TCP and Reno/CUBIC control\n");
	pr_notice("tcpcc: M5.1 hosted L3 netdevice passed (%llu rx, %llu tx, %llu rx drops)\n",
		  (unsigned long long)l3_stats.rx_packets,
		  (unsigned long long)l3_stats.tx_packets,
		  (unsigned long long)l3_stats.rx_dropped);
	panic("tcpcc: M5.1 reached hosted L3 netdevice boundary after packet-fd validation");
}
/*
 * Run after ordinary late initcalls such as sch_default_qdisc(), because M6.1
 * attaches tcpcc0 and validates the configured default fq qdisc at runtime.
 */
late_initcall_sync(tcpcc_control_selftest);

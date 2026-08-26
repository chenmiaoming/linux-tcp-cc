// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/panic.h>
#include <linux/sched.h>
#include <linux/sockptr.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <asm/bridge.h>
#include <asm/host.h>
#include <asm/l3net.h>

#define TCPCC_CONTROL_IRQ          2
#define TCPCC_CONTROL_MAGIC        0x32434354U /* "TCC2" on x86-64 */
#define TCPCC_CONTROL_VERSION      1
#define TCPCC_CONTROL_MAX_SOCKETS  16
#define TCPCC_CONTROL_MAX_PAYLOAD  256
#define TCPCC_CONTROL_HOST_BACKEND_BYTES 192
#define TCPCC_CONTROL_HOST_BACKEND_TIMEOUT_MS 3000
#define TCPCC_CONTROL_HOST_BACKEND_SLOT 1U
#define TCPCC_CONTROL_HOST_BACKEND_GENERATION 0x4d3823U
#define TCPCC_CONTROL_HOST_BACKEND_TOKEN \
	TCPCC_HOST_EVENT_RUNTIME_TOKEN(TCPCC_CONTROL_HOST_BACKEND_SLOT, \
				       TCPCC_CONTROL_HOST_BACKEND_GENERATION)

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
	TCPCC_CONTROL_TCP_INFO,
	TCPCC_CONTROL_HOST_BACKEND_PROBE,
	TCPCC_CONTROL_BRIDGE_START,
	TCPCC_CONTROL_BRIDGE_JOIN,
	TCPCC_CONTROL_BRIDGE_CANCEL,
	TCPCC_CONTROL_ACCEPT_NONBLOCK,
	TCPCC_CONTROL_SHUTDOWN,
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

/*
 * Stable project-side subset of Linux struct tcp_info. Keep this independent
 * of the UAPI struct's future growth so the version-1 control record remains
 * fixed at 64 bytes for the x86-64 hosted test ABI.
 */
struct tcpcc_control_tcp_info {
	u8 state;
	u8 ca_state;
	u16 reserved;
	u32 rto_us;
	u32 rtt_us;
	u32 rttvar_us;
	u32 snd_cwnd;
	u32 snd_ssthresh;
	u32 unacked;
	u32 lost;
	u32 retrans;
	u32 total_retrans;
	u64 pacing_rate;
	u64 max_pacing_rate;
	u64 delivery_rate;
};

struct tcpcc_control_host_backend_result {
	u64 token;
	s32 connect_status;
	u32 connect_events;
	u32 terminal_events;
	u32 tx_bytes;
	u32 rx_bytes;
	u32 reserved;
};

static struct socket *tcpcc_control_sockets[TCPCC_CONTROL_MAX_SOCKETS];
static struct completion tcpcc_control_request_ready;
static struct completion tcpcc_control_finished;
static struct task_struct *tcpcc_control_task;
static int tcpcc_control_result;
static u16 tcpcc_control_terminal_op;

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

static int tcpcc_control_accept_flags(
				const struct tcpcc_control_request *request,
				struct tcpcc_control_response *response,
				int flags)
{
	struct socket *listener = tcpcc_control_lookup(request->handle);
	struct socket *accepted;
	int handle;
	int ret;

	if (!listener)
		return -EBADF;

	ret = kernel_accept(listener, &accepted, flags);
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

static int tcpcc_control_accept(const struct tcpcc_control_request *request,
				struct tcpcc_control_response *response)
{
	return tcpcc_control_accept_flags(request, response, 0);
}

static int tcpcc_control_accept_nonblock(
				const struct tcpcc_control_request *request,
				struct tcpcc_control_response *response)
{
	return tcpcc_control_accept_flags(request, response, O_NONBLOCK);
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

static int tcpcc_control_tcp_info(const struct tcpcc_control_request *request,
				  struct tcpcc_control_response *response)
{
	struct tcpcc_control_tcp_info snapshot = { };
	struct socket *sock = tcpcc_control_lookup(request->handle);
	struct tcp_info info = { };
	int len = sizeof(info);
	int ret;

	if (!sock)
		return -EBADF;

	BUILD_BUG_ON(sizeof(snapshot) != 64);
	BUILD_BUG_ON(sizeof(snapshot) > TCPCC_CONTROL_MAX_PAYLOAD);

	/*
	 * Use the ordinary upstream TCP_INFO getsockopt path so locking and the
	 * snapshot semantics stay owned by native Linux TCP. ARCH=tcpcc only
	 * narrows the result into its stable host-control record.
	 */
	ret = do_tcp_getsockopt(sock->sk, SOL_TCP, TCP_INFO,
				KERNEL_SOCKPTR(&info), KERNEL_SOCKPTR(&len));
	if (ret)
		return ret;

	snapshot.state = info.tcpi_state;
	snapshot.ca_state = info.tcpi_ca_state;
	snapshot.rto_us = info.tcpi_rto;
	snapshot.rtt_us = info.tcpi_rtt;
	snapshot.rttvar_us = info.tcpi_rttvar;
	snapshot.snd_cwnd = info.tcpi_snd_cwnd;
	snapshot.snd_ssthresh = info.tcpi_snd_ssthresh;
	snapshot.unacked = info.tcpi_unacked;
	snapshot.lost = info.tcpi_lost;
	snapshot.retrans = info.tcpi_retrans;
	snapshot.total_retrans = info.tcpi_total_retrans;
	snapshot.pacing_rate = info.tcpi_pacing_rate;
	snapshot.max_pacing_rate = info.tcpi_max_pacing_rate;
	snapshot.delivery_rate = info.tcpi_delivery_rate;

	memcpy(response->data, &snapshot, sizeof(snapshot));
	response->length = sizeof(snapshot);
	return 0;
}

static u8 tcpcc_control_host_backend_byte(size_t offset)
{
	return (u8)((offset * 37U + 11U) & 0xffU);
}

static int tcpcc_control_host_backend_wait(struct tcpcc_host_event *event)
{
	int ret;

	ret = tcpcc_host_runtime_event_wait_timeout(
		event, msecs_to_jiffies(TCPCC_CONTROL_HOST_BACKEND_TIMEOUT_MS));
	if (ret)
		return ret;
	if (event->token != TCPCC_CONTROL_HOST_BACKEND_TOKEN)
		return -ESTALE;
	return 0;
}

static int tcpcc_control_host_backend_check_error(int fd,
						  u32 events)
{
	int ret;

	if (!(events & TCPCC_HOST_EVENT_ERROR))
		return 0;

	ret = tcpcc_host_socket_error(fd);
	return ret ? ret : -EIO;
}

static int tcpcc_control_host_backend_send(
				struct tcpcc_control_host_backend_result *result,
				int fd)
{
	u8 payload[TCPCC_CONTROL_HOST_BACKEND_BYTES];
	size_t offset;

	for (offset = 0; offset < sizeof(payload); offset++)
		payload[offset] = tcpcc_control_host_backend_byte(offset);

	offset = 0;
	while (offset < sizeof(payload)) {
		ssize_t ret = tcpcc_host_send_fd(fd, payload + offset,
						 sizeof(payload) - offset);

		if (ret == -EAGAIN) {
			struct tcpcc_host_event event;
			int wait_ret;

			wait_ret = tcpcc_control_host_backend_wait(&event);
			if (wait_ret)
				return wait_ret;
			wait_ret = tcpcc_control_host_backend_check_error(
				fd, event.events);
			if (wait_ret)
				return wait_ret;
			if (event.events & TCPCC_HOST_EVENT_HANGUP)
				return -EPIPE;
			if (!(event.events & TCPCC_HOST_EVENT_WRITABLE))
				return -EIO;
			continue;
		}
		if (ret < 0)
			return (int)ret;
		if (!ret)
			return -EIO;
		offset += ret;
	}

	result->tx_bytes = offset;
	return 0;
}

static int tcpcc_control_host_backend_recv(
				struct tcpcc_control_host_backend_result *result,
				int fd)
{
	u8 buffer[64];
	size_t offset = 0;
	bool eof = false;

	while (!eof) {
		struct tcpcc_host_event event;
		int ret;

		ret = tcpcc_control_host_backend_wait(&event);
		if (ret)
			return ret;
		result->terminal_events |= event.events;

		ret = tcpcc_control_host_backend_check_error(fd, event.events);
		if (ret)
			return ret;
		if (!(event.events & (TCPCC_HOST_EVENT_READABLE |
				      TCPCC_HOST_EVENT_HANGUP)))
			return -EIO;

		for (;;) {
			size_t length = offset < TCPCC_CONTROL_HOST_BACKEND_BYTES ?
				min_t(size_t, sizeof(buffer),
				      TCPCC_CONTROL_HOST_BACKEND_BYTES - offset) : 1;
			ssize_t io_ret;
			size_t i;

			io_ret = tcpcc_host_recv_fd(fd, buffer, length);
			if (io_ret == -EAGAIN)
				break;
			if (io_ret < 0)
				return (int)io_ret;
			if (!io_ret) {
				eof = true;
				break;
			}
			if (offset >= TCPCC_CONTROL_HOST_BACKEND_BYTES)
				return -EMSGSIZE;

			for (i = 0; i < io_ret; i++) {
				if (buffer[i] !=
				    tcpcc_control_host_backend_byte(offset + i))
					return -EBADMSG;
			}
			offset += io_ret;
		}

		if (!eof && event.events & TCPCC_HOST_EVENT_HANGUP)
			return -EIO;
	}

	/* FIN may race the first readable edge after the echoed payload. */
	if (!(result->terminal_events & TCPCC_HOST_EVENT_HANGUP)) {
		struct tcpcc_host_event event;
		int ret;

		ret = tcpcc_control_host_backend_wait(&event);
		if (ret)
			return ret;
		result->terminal_events |= event.events;
		ret = tcpcc_control_host_backend_check_error(fd, event.events);
		if (ret)
			return ret;
	}

	if (offset != TCPCC_CONTROL_HOST_BACKEND_BYTES ||
	    !(result->terminal_events & TCPCC_HOST_EVENT_HANGUP))
		return -EIO;
	result->rx_bytes = offset;
	return 0;
}

static int tcpcc_control_host_backend_probe(
				const struct tcpcc_control_request *request,
				struct tcpcc_control_response *response)
{
	struct tcpcc_control_host_backend_result result = {
		.token = TCPCC_CONTROL_HOST_BACKEND_TOKEN,
	};
	struct tcpcc_host_event event;
	bool registered = false;
	int fd = -1;
	int ret;

	BUILD_BUG_ON(sizeof(result) != 32);
	BUILD_BUG_ON(sizeof(result) > TCPCC_CONTROL_MAX_PAYLOAD);

	/* This diagnostic operation configures only a host-loopback endpoint. */
	if (request->handle || request->length || request->arg0 != INADDR_LOOPBACK ||
	    !request->arg1 || request->arg1 > 0xffffU)
		return -EINVAL;
	if (tcpcc_bridge_active())
		return -EBUSY;

	fd = tcpcc_host_tcp_socket();
	if (fd < 0)
		return fd;

	ret = tcpcc_host_event_add_mask(fd, result.token,
					TCPCC_HOST_EVENT_WRITABLE, true);
	if (ret)
		goto out;
	registered = true;

	ret = tcpcc_host_tcp_connect(fd, htonl(request->arg0),
				     htons((u16)request->arg1));
	result.connect_status = ret;
	if (ret && ret != -EINPROGRESS)
		goto out;

	ret = tcpcc_control_host_backend_wait(&event);
	if (ret)
		goto out;
	result.connect_events = event.events;
	if (!(event.events & (TCPCC_HOST_EVENT_WRITABLE |
			      TCPCC_HOST_EVENT_ERROR))) {
		ret = -EIO;
		goto out;
	}
	ret = tcpcc_host_socket_error(fd);
	if (ret)
		goto out;
	if (!(event.events & TCPCC_HOST_EVENT_WRITABLE)) {
		ret = -EIO;
		goto out;
	}

	ret = tcpcc_control_host_backend_send(&result, fd);
	if (ret)
		goto out;
	ret = tcpcc_host_shutdown(fd, TCPCC_HOST_SHUT_WR);
	if (ret)
		goto out;

	ret = tcpcc_host_event_mod_mask(fd, result.token,
					TCPCC_HOST_EVENT_READABLE, true);
	if (ret)
		goto out;
	ret = tcpcc_control_host_backend_recv(&result, fd);
	if (ret)
		goto out;

	memcpy(response->data, &result, sizeof(result));
	response->length = sizeof(result);
out:
	if (registered) {
		int del_ret = tcpcc_host_event_del(fd);

		if (!ret && del_ret)
			ret = del_ret;
	}
	if (fd >= 0) {
		int close_ret = tcpcc_host_close(fd);

		if (!ret && close_ret)
			ret = close_ret;
	}
	if (!ret)
		pr_notice("tcpcc: M8.2.3 nonblocking host TCP backend probe passed (%u bytes each direction)\n",
			  result.tx_bytes);
	return ret;
}

static int tcpcc_control_bridge_start(
				const struct tcpcc_control_request *request,
				struct tcpcc_control_response *response)
{
	struct socket *public_sock = tcpcc_control_lookup(request->handle);
	int bridge_handle;
	int ret;

	if (!public_sock)
		return -EBADF;
	if (request->length || request->arg0 != INADDR_LOOPBACK ||
	    !request->arg1 || request->arg1 > 0xffffU)
		return -EINVAL;
	if (public_sock->sk->sk_state != TCP_ESTABLISHED)
		return -ENOTCONN;

	ret = tcpcc_bridge_start(public_sock, htonl(request->arg0),
				 htons((u16)request->arg1), &bridge_handle);
	if (ret)
		return ret;

	/* tcpcc_bridge_start() owns the accepted socket after success. */
	tcpcc_control_sockets[request->handle - 1] = NULL;
	response->handle = bridge_handle;
	return 0;
}

static int tcpcc_control_bridge_join(
				const struct tcpcc_control_request *request,
				struct tcpcc_control_response *response)
{
	struct tcpcc_bridge_result result;
	int ret;

	BUILD_BUG_ON(sizeof(result) != 64);
	BUILD_BUG_ON(sizeof(result) > TCPCC_CONTROL_MAX_PAYLOAD);

	if (request->length || request->arg1 || !request->arg0 ||
	    request->arg0 > 30000U)
		return -EINVAL;

	ret = tcpcc_bridge_join(request->handle,
				msecs_to_jiffies(request->arg0), &result);
	if (ret)
		return ret;

	memcpy(response->data, &result, sizeof(result));
	response->length = sizeof(result);
	pr_notice("tcpcc: M8.2.5 session %d bridge joined (%llu public-to-backend, %llu backend-to-public bytes, %u send EAGAIN, %u-byte buffers)\n",
		  request->handle,
		  (unsigned long long)result.public_to_backend_bytes,
		  (unsigned long long)result.backend_to_public_bytes,
		  result.host_send_eagain,
		  result.buffer_limit);
	return 0;
}

static int tcpcc_control_bridge_cancel(
				const struct tcpcc_control_request *request)
{
	int ret;

	if (request->length || request->arg0 || request->arg1)
		return -EINVAL;

	ret = tcpcc_bridge_cancel_session(request->handle);
	if (!ret)
		pr_notice("tcpcc: M8.2.6 session %d cancel requested\n",
			  request->handle);
	return ret;
}

static int tcpcc_control_shutdown(const struct tcpcc_control_request *request)
{
	if (request->handle || request->arg0 || request->arg1 || request->length)
		return -EINVAL;
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
	case TCPCC_CONTROL_TCP_INFO:
		return tcpcc_control_tcp_info(request, response);
	case TCPCC_CONTROL_HOST_BACKEND_PROBE:
		return tcpcc_control_host_backend_probe(request, response);
	case TCPCC_CONTROL_BRIDGE_START:
		return tcpcc_control_bridge_start(request, response);
	case TCPCC_CONTROL_BRIDGE_JOIN:
		return tcpcc_control_bridge_join(request, response);
	case TCPCC_CONTROL_BRIDGE_CANCEL:
		return tcpcc_control_bridge_cancel(request);
	case TCPCC_CONTROL_ACCEPT_NONBLOCK:
		return tcpcc_control_accept_nonblock(request, response);
	case TCPCC_CONTROL_SHUTDOWN:
		return tcpcc_control_shutdown(request);
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

		if (request.op == TCPCC_CONTROL_FINISH ||
		    (request.op == TCPCC_CONTROL_SHUTDOWN &&
		     !response.status)) {
			tcpcc_control_result = response.status;
			tcpcc_control_terminal_op = request.op;
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
	tcpcc_control_terminal_op = 0;

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
	tcpcc_bridge_cancel();
	tcpcc_control_release_all();

	if (!tcpcc_control_result) {
		ret = tcpcc_l3_get_stats(&l3_stats);
		if (ret)
			tcpcc_control_result = ret;
	}

	tcpcc_l3_teardown();
	if (!tcpcc_control_result &&
	    tcpcc_control_terminal_op == TCPCC_CONTROL_SHUTDOWN) {
		pr_notice("tcpcc: M8.4 hosted runtime stopped cleanly\n");
		tcpcc_host_exit(0);
	}

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

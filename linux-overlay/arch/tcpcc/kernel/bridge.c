// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <asm/bridge.h>
#include <asm/host.h>

#define TCPCC_BRIDGE_RUNTIME_SLOT 2U
#define TCPCC_BRIDGE_CONNECT_TIMEOUT_MS 3000
#define TCPCC_BRIDGE_EVENT_POLL_MS 100

struct tcpcc_bridge_state {
	struct socket *public_sock;
	int host_fd;
	u64 token;
	bool registered;
	bool active;
	bool running;
	bool stopping;
	int status;
	u32 read_events;
	u32 write_events;
	u32 terminal_events;
	u64 public_to_backend_bytes;
	u64 backend_to_public_bytes;
	spinlock_t lock;
	atomic_t directions_done;
	struct completion start;
	struct completion finished;
	struct completion host_readable;
	struct completion host_writable;
	struct task_struct *event_task;
	struct task_struct *public_to_backend_task;
	struct task_struct *backend_to_public_task;
	u8 public_to_backend_buffer[TCPCC_BRIDGE_BUFFER_LIMIT];
	u8 backend_to_public_buffer[TCPCC_BRIDGE_BUFFER_LIMIT];
};

static DEFINE_MUTEX(tcpcc_bridge_control_lock);
static struct tcpcc_bridge_state tcpcc_bridge;
static u32 tcpcc_bridge_generation;

static u32 tcpcc_bridge_next_generation(void)
{
	tcpcc_bridge_generation++;
	tcpcc_bridge_generation &= TCPCC_HOST_EVENT_RUNTIME_GENERATION_MASK;
	if (!tcpcc_bridge_generation)
		tcpcc_bridge_generation = 1;
	return tcpcc_bridge_generation;
}

static void tcpcc_bridge_stop(int status, bool abort_sockets)
{
	unsigned long flags;
	bool first = false;

	spin_lock_irqsave(&tcpcc_bridge.lock, flags);
	if (status && !tcpcc_bridge.status)
		tcpcc_bridge.status = status;
	if (!tcpcc_bridge.stopping) {
		tcpcc_bridge.stopping = true;
		first = true;
	}
	spin_unlock_irqrestore(&tcpcc_bridge.lock, flags);

	complete_all(&tcpcc_bridge.host_readable);
	complete_all(&tcpcc_bridge.host_writable);
	if (!first || !abort_sockets)
		return;

	if (tcpcc_bridge.host_fd >= 0)
		tcpcc_host_shutdown(tcpcc_bridge.host_fd,
				    TCPCC_HOST_SHUT_RDWR);
	if (tcpcc_bridge.public_sock)
		kernel_sock_shutdown(tcpcc_bridge.public_sock, SHUT_RDWR);
}

static void tcpcc_bridge_direction_done(int status)
{
	if (status)
		tcpcc_bridge_stop(status, true);
	if (atomic_inc_return(&tcpcc_bridge.directions_done) != 2)
		return;

	tcpcc_bridge_stop(0, false);
	complete(&tcpcc_bridge.finished);
}

static int tcpcc_bridge_wait_host(struct completion *ready, u32 *pending,
				  u32 wanted)
{
	for (;;) {
		unsigned long flags;
		u32 events;
		int status;
		bool stopping;

		wait_for_completion(ready);
		spin_lock_irqsave(&tcpcc_bridge.lock, flags);
		events = *pending;
		*pending = 0;
		status = tcpcc_bridge.status;
		stopping = tcpcc_bridge.stopping;
		spin_unlock_irqrestore(&tcpcc_bridge.lock, flags);

		if (status)
			return status;
		if (stopping)
			return -ECANCELED;
		if (events & (wanted | TCPCC_HOST_EVENT_HANGUP))
			return 0;
	}
}

static int tcpcc_bridge_event_thread(void *unused)
{
	wait_for_completion(&tcpcc_bridge.start);
	if (!READ_ONCE(tcpcc_bridge.running))
		return 0;

	while (!kthread_should_stop() && !READ_ONCE(tcpcc_bridge.stopping)) {
		struct tcpcc_host_event event;
		unsigned long flags;
		bool wake_read;
		bool wake_write;
		int ret;

		ret = tcpcc_host_runtime_event_wait_timeout(
			&event, msecs_to_jiffies(TCPCC_BRIDGE_EVENT_POLL_MS));
		if (ret == -ETIMEDOUT)
			continue;
		if (ret) {
			tcpcc_bridge_stop(ret, true);
			break;
		}
		if (READ_ONCE(tcpcc_bridge.stopping))
			break;
		if (event.token != tcpcc_bridge.token) {
			tcpcc_bridge_stop(-ESTALE, true);
			break;
		}

		if (event.events & TCPCC_HOST_EVENT_ERROR) {
			spin_lock_irqsave(&tcpcc_bridge.lock, flags);
			tcpcc_bridge.terminal_events |= TCPCC_HOST_EVENT_ERROR;
			spin_unlock_irqrestore(&tcpcc_bridge.lock, flags);
			ret = tcpcc_host_socket_error(tcpcc_bridge.host_fd);
			tcpcc_bridge_stop(ret ? ret : -EIO, true);
			break;
		}

		wake_read = event.events & (TCPCC_HOST_EVENT_READABLE |
					    TCPCC_HOST_EVENT_HANGUP);
		wake_write = event.events & (TCPCC_HOST_EVENT_WRITABLE |
					     TCPCC_HOST_EVENT_HANGUP);
		spin_lock_irqsave(&tcpcc_bridge.lock, flags);
		if (wake_read)
			tcpcc_bridge.read_events |= event.events;
		if (wake_write)
			tcpcc_bridge.write_events |= event.events;
		tcpcc_bridge.terminal_events |=
			event.events & TCPCC_HOST_EVENT_HANGUP;
		spin_unlock_irqrestore(&tcpcc_bridge.lock, flags);

		if (wake_read)
			complete(&tcpcc_bridge.host_readable);
		if (wake_write)
			complete(&tcpcc_bridge.host_writable);
	}

	return 0;
}

static int tcpcc_bridge_public_to_backend_thread(void *unused)
{
	int status = 0;

	wait_for_completion(&tcpcc_bridge.start);
	if (!READ_ONCE(tcpcc_bridge.running))
		return 0;

	while (!READ_ONCE(tcpcc_bridge.stopping)) {
		struct msghdr msg = { };
		struct kvec vec = {
			.iov_base = tcpcc_bridge.public_to_backend_buffer,
			.iov_len = TCPCC_BRIDGE_BUFFER_LIMIT,
		};
		size_t offset = 0;
		int received;

		received = kernel_recvmsg(tcpcc_bridge.public_sock, &msg, &vec, 1,
					  TCPCC_BRIDGE_BUFFER_LIMIT, 0);
		if (READ_ONCE(tcpcc_bridge.stopping))
			break;
		if (received < 0) {
			status = received;
			break;
		}
		if (!received) {
			status = tcpcc_host_shutdown(tcpcc_bridge.host_fd,
						     TCPCC_HOST_SHUT_WR);
			break;
		}

		while (offset < (size_t)received) {
			ssize_t sent;

			sent = tcpcc_host_send_fd(
				tcpcc_bridge.host_fd,
				tcpcc_bridge.public_to_backend_buffer + offset,
				(size_t)received - offset);
			if (sent == -EAGAIN) {
				status = tcpcc_bridge_wait_host(
					&tcpcc_bridge.host_writable,
					&tcpcc_bridge.write_events,
					TCPCC_HOST_EVENT_WRITABLE);
				if (status)
					break;
				continue;
			}
			if (sent < 0) {
				status = (int)sent;
				break;
			}
			if (!sent) {
				status = -EIO;
				break;
			}
			offset += sent;
			tcpcc_bridge.public_to_backend_bytes += sent;
		}
		if (status)
			break;
	}

	tcpcc_bridge_direction_done(status);
	return status;
}

static int tcpcc_bridge_send_public(const u8 *buffer, size_t length)
{
	size_t offset = 0;

	while (offset < length) {
		struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
		struct kvec vec = {
			.iov_base = (void *)(buffer + offset),
			.iov_len = length - offset,
		};
		int sent;

		sent = kernel_sendmsg(tcpcc_bridge.public_sock, &msg, &vec, 1,
				      length - offset);
		if (sent < 0)
			return sent;
		if (!sent)
			return -EIO;
		offset += sent;
		tcpcc_bridge.backend_to_public_bytes += sent;
	}

	return 0;
}

static int tcpcc_bridge_backend_to_public_thread(void *unused)
{
	bool host_ready = false;
	int status = 0;

	wait_for_completion(&tcpcc_bridge.start);
	if (!READ_ONCE(tcpcc_bridge.running))
		return 0;

	while (!READ_ONCE(tcpcc_bridge.stopping)) {
		ssize_t received;

		if (!host_ready) {
			status = tcpcc_bridge_wait_host(
				&tcpcc_bridge.host_readable,
				&tcpcc_bridge.read_events,
				TCPCC_HOST_EVENT_READABLE);
			if (status)
				break;
			host_ready = true;
		}

		received = tcpcc_host_recv_fd(
			tcpcc_bridge.host_fd,
			tcpcc_bridge.backend_to_public_buffer,
			TCPCC_BRIDGE_BUFFER_LIMIT);
		if (received == -EAGAIN) {
			host_ready = false;
			continue;
		}
		if (received < 0) {
			status = (int)received;
			break;
		}
		if (!received) {
			status = kernel_sock_shutdown(tcpcc_bridge.public_sock,
						      SHUT_WR);
			break;
		}

		status = tcpcc_bridge_send_public(
			tcpcc_bridge.backend_to_public_buffer, received);
		if (status)
			break;
		/* Keep draining until EAGAIN so edge-triggered readiness is safe. */
	}

	tcpcc_bridge_direction_done(status);
	return status;
}

static int tcpcc_bridge_connect(__be32 address, __be16 port)
{
	struct tcpcc_host_event event;
	int ret;

	ret = tcpcc_host_event_add_mask(tcpcc_bridge.host_fd,
					tcpcc_bridge.token,
					TCPCC_HOST_EVENT_WRITABLE, true);
	if (ret)
		return ret;
	tcpcc_bridge.registered = true;

	ret = tcpcc_host_tcp_connect(tcpcc_bridge.host_fd, address, port);
	if (ret && ret != -EINPROGRESS)
		return ret;

	ret = tcpcc_host_runtime_event_wait_timeout(
		&event, msecs_to_jiffies(TCPCC_BRIDGE_CONNECT_TIMEOUT_MS));
	if (ret)
		return ret;
	if (event.token != tcpcc_bridge.token)
		return -ESTALE;
	if (!(event.events & (TCPCC_HOST_EVENT_WRITABLE |
			      TCPCC_HOST_EVENT_ERROR)))
		return -EIO;

	ret = tcpcc_host_socket_error(tcpcc_bridge.host_fd);
	if (ret)
		return ret;
	if (!(event.events & TCPCC_HOST_EVENT_WRITABLE))
		return -EIO;
	return 0;
}

static void tcpcc_bridge_stop_setup_tasks(void)
{
	WRITE_ONCE(tcpcc_bridge.running, false);
	complete_all(&tcpcc_bridge.start);
	if (tcpcc_bridge.event_task)
		kthread_stop(tcpcc_bridge.event_task);
	if (tcpcc_bridge.public_to_backend_task)
		kthread_stop(tcpcc_bridge.public_to_backend_task);
	if (tcpcc_bridge.backend_to_public_task)
		kthread_stop(tcpcc_bridge.backend_to_public_task);
	tcpcc_bridge.event_task = NULL;
	tcpcc_bridge.public_to_backend_task = NULL;
	tcpcc_bridge.backend_to_public_task = NULL;
}

static void tcpcc_bridge_close_host(void)
{
	if (tcpcc_bridge.registered) {
		tcpcc_host_event_del(tcpcc_bridge.host_fd);
		tcpcc_bridge.registered = false;
	}
	if (tcpcc_bridge.host_fd >= 0) {
		tcpcc_host_close(tcpcc_bridge.host_fd);
		tcpcc_bridge.host_fd = -1;
	}
}

int tcpcc_bridge_start(struct socket *public_sock, __be32 backend_address,
		       __be16 backend_port, int *handle)
{
	int ret;

	mutex_lock(&tcpcc_bridge_control_lock);
	if (tcpcc_bridge.active) {
		ret = -EBUSY;
		goto unlock;
	}

	memset(&tcpcc_bridge, 0, sizeof(tcpcc_bridge));
	tcpcc_bridge.public_sock = public_sock;
	tcpcc_bridge.host_fd = -1;
	tcpcc_bridge.token = TCPCC_HOST_EVENT_RUNTIME_TOKEN(
		TCPCC_BRIDGE_RUNTIME_SLOT, tcpcc_bridge_next_generation());
	spin_lock_init(&tcpcc_bridge.lock);
	atomic_set(&tcpcc_bridge.directions_done, 0);
	init_completion(&tcpcc_bridge.start);
	init_completion(&tcpcc_bridge.finished);
	init_completion(&tcpcc_bridge.host_readable);
	init_completion(&tcpcc_bridge.host_writable);

	tcpcc_bridge.host_fd = tcpcc_host_tcp_socket();
	if (tcpcc_bridge.host_fd < 0) {
		ret = tcpcc_bridge.host_fd;
		goto reset;
	}
	ret = tcpcc_bridge_connect(backend_address, backend_port);
	if (ret)
		goto close_host;

	tcpcc_bridge.event_task = kthread_run(tcpcc_bridge_event_thread, NULL,
					       "tcpcc-m8.2-events");
	if (IS_ERR(tcpcc_bridge.event_task)) {
		ret = PTR_ERR(tcpcc_bridge.event_task);
		tcpcc_bridge.event_task = NULL;
		goto close_host;
	}
	tcpcc_bridge.public_to_backend_task = kthread_run(
		tcpcc_bridge_public_to_backend_thread, NULL, "tcpcc-m8.2-p2b");
	if (IS_ERR(tcpcc_bridge.public_to_backend_task)) {
		ret = PTR_ERR(tcpcc_bridge.public_to_backend_task);
		tcpcc_bridge.public_to_backend_task = NULL;
		goto stop_tasks;
	}
	tcpcc_bridge.backend_to_public_task = kthread_run(
		tcpcc_bridge_backend_to_public_thread, NULL, "tcpcc-m8.2-b2p");
	if (IS_ERR(tcpcc_bridge.backend_to_public_task)) {
		ret = PTR_ERR(tcpcc_bridge.backend_to_public_task);
		tcpcc_bridge.backend_to_public_task = NULL;
		goto stop_tasks;
	}

	ret = tcpcc_host_event_mod_mask(
		tcpcc_bridge.host_fd, tcpcc_bridge.token,
		TCPCC_HOST_EVENT_READABLE | TCPCC_HOST_EVENT_WRITABLE, true);
	if (ret)
		goto stop_tasks;

	tcpcc_bridge.active = true;
	WRITE_ONCE(tcpcc_bridge.running, true);
	*handle = TCPCC_BRIDGE_HANDLE;
	complete_all(&tcpcc_bridge.start);
	mutex_unlock(&tcpcc_bridge_control_lock);
	return 0;

stop_tasks:
	tcpcc_bridge_stop_setup_tasks();
close_host:
	tcpcc_bridge_close_host();
reset:
	tcpcc_bridge.public_sock = NULL;
unlock:
	mutex_unlock(&tcpcc_bridge_control_lock);
	return ret;
}

static int tcpcc_bridge_reap(struct tcpcc_bridge_result *result)
{
	int cleanup_status = 0;
	int status;

	if (tcpcc_bridge.event_task)
		kthread_stop(tcpcc_bridge.event_task);
	if (tcpcc_bridge.public_to_backend_task)
		kthread_stop(tcpcc_bridge.public_to_backend_task);
	if (tcpcc_bridge.backend_to_public_task)
		kthread_stop(tcpcc_bridge.backend_to_public_task);

	if (tcpcc_bridge.registered) {
		cleanup_status = tcpcc_host_event_del(tcpcc_bridge.host_fd);
		tcpcc_bridge.registered = false;
	}
	if (tcpcc_bridge.host_fd >= 0) {
		int ret = tcpcc_host_close(tcpcc_bridge.host_fd);

		if (!cleanup_status && ret)
			cleanup_status = ret;
		tcpcc_bridge.host_fd = -1;
	}
	if (tcpcc_bridge.public_sock) {
		kernel_sock_shutdown(tcpcc_bridge.public_sock, SHUT_RDWR);
		sock_release(tcpcc_bridge.public_sock);
		tcpcc_bridge.public_sock = NULL;
	}

	status = tcpcc_bridge.status ? tcpcc_bridge.status : cleanup_status;
	if (result) {
		memset(result, 0, sizeof(*result));
		result->token = tcpcc_bridge.token;
		result->public_to_backend_bytes =
			tcpcc_bridge.public_to_backend_bytes;
		result->backend_to_public_bytes =
			tcpcc_bridge.backend_to_public_bytes;
		result->buffer_limit = TCPCC_BRIDGE_BUFFER_LIMIT;
		result->terminal_events = tcpcc_bridge.terminal_events;
		result->status = status;
	}

	tcpcc_bridge.active = false;
	WRITE_ONCE(tcpcc_bridge.running, false);
	tcpcc_bridge.event_task = NULL;
	tcpcc_bridge.public_to_backend_task = NULL;
	tcpcc_bridge.backend_to_public_task = NULL;
	return status;
}

int tcpcc_bridge_join(int handle, unsigned long timeout,
		      struct tcpcc_bridge_result *result)
{
	int ret;

	mutex_lock(&tcpcc_bridge_control_lock);
	if (!tcpcc_bridge.active || handle != TCPCC_BRIDGE_HANDLE) {
		ret = -ENOENT;
		goto unlock;
	}
	if (!wait_for_completion_timeout(&tcpcc_bridge.finished, timeout)) {
		ret = -ETIMEDOUT;
		goto unlock;
	}

	ret = tcpcc_bridge_reap(result);
unlock:
	mutex_unlock(&tcpcc_bridge_control_lock);
	return ret;
}

bool tcpcc_bridge_active(void)
{
	bool active;

	mutex_lock(&tcpcc_bridge_control_lock);
	active = tcpcc_bridge.active;
	mutex_unlock(&tcpcc_bridge_control_lock);
	return active;
}

void tcpcc_bridge_cancel(void)
{
	mutex_lock(&tcpcc_bridge_control_lock);
	if (!tcpcc_bridge.active)
		goto unlock;

	tcpcc_bridge_stop(-ECANCELED, true);
	wait_for_completion(&tcpcc_bridge.finished);
	tcpcc_bridge_reap(NULL);
unlock:
	mutex_unlock(&tcpcc_bridge_control_lock);
}

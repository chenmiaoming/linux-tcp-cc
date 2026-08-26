// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/sched/task.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <asm/bridge.h>
#include <asm/host.h>

#define TCPCC_BRIDGE_CONNECT_TIMEOUT_MS 3000
#define TCPCC_BRIDGE_EVENT_POLL_MS 100

struct tcpcc_bridge_session {
	spinlock_t lock;
	struct socket *public_sock;
	int host_fd;
	int handle;
	u64 token;
	u32 generation;
	u32 index;
	bool allocated;
	bool accept_events;
	bool registered;
	bool connecting;
	bool running;
	bool stopping;
	int status;
	u32 connect_events;
	u32 read_events;
	u32 write_events;
	u32 terminal_events;
	u32 host_send_eagain;
	u32 host_partial_writes;
	u32 host_recv_eagain;
	u64 public_to_backend_bytes;
	u64 backend_to_public_bytes;
	atomic_t directions_done;
	atomic_t event_refs;
	struct completion start;
	struct completion finished;
	struct completion connect_ready;
	struct completion host_readable;
	struct completion host_writable;
	struct completion event_idle;
	struct task_struct *public_to_backend_task;
	struct task_struct *backend_to_public_task;
	u8 public_to_backend_buffer[TCPCC_BRIDGE_BUFFER_LIMIT];
	u8 backend_to_public_buffer[TCPCC_BRIDGE_BUFFER_LIMIT];
};

struct tcpcc_bridge_manager {
	bool initialized;
	bool dispatcher_running;
	bool dispatcher_stopping;
	int dispatcher_status;
	unsigned int active_sessions;
	struct completion dispatcher_start;
	struct task_struct *dispatcher_task;
	struct tcpcc_bridge_session sessions[TCPCC_BRIDGE_SESSION_LIMIT];
};

static DEFINE_MUTEX(tcpcc_bridge_control_lock);
static struct tcpcc_bridge_manager tcpcc_bridge_manager;

static int tcpcc_bridge_make_handle(unsigned int index, u32 generation)
{
	return (int)((generation << TCPCC_BRIDGE_HANDLE_SLOT_BITS) |
		     (index + 1U));
}

static u32 tcpcc_bridge_next_generation(u32 generation)
{
	generation++;
	generation &= TCPCC_BRIDGE_HANDLE_GENERATION_MASK;
	if (!generation)
		generation = 1;
	return generation;
}

static void tcpcc_bridge_manager_init(void)
{
	unsigned int index;

	if (tcpcc_bridge_manager.initialized)
		return;

	for (index = 0; index < TCPCC_BRIDGE_SESSION_LIMIT; index++) {
		spin_lock_init(&tcpcc_bridge_manager.sessions[index].lock);
		tcpcc_bridge_manager.sessions[index].host_fd = -1;
	}
	init_completion(&tcpcc_bridge_manager.dispatcher_start);
	tcpcc_bridge_manager.initialized = true;
}

static void tcpcc_bridge_session_stop(struct tcpcc_bridge_session *session,
				      int status, bool abort_sockets)
{
	unsigned long flags;
	bool first = false;

	spin_lock_irqsave(&session->lock, flags);
	if (!session->allocated) {
		spin_unlock_irqrestore(&session->lock, flags);
		return;
	}
	if (status && !session->status)
		session->status = status;
	if (!session->stopping) {
		session->stopping = true;
		first = true;
	}
	spin_unlock_irqrestore(&session->lock, flags);

	complete_all(&session->connect_ready);
	complete_all(&session->host_readable);
	complete_all(&session->host_writable);
	if (!first || !abort_sockets)
		return;

	if (session->host_fd >= 0)
		tcpcc_host_shutdown(session->host_fd, TCPCC_HOST_SHUT_RDWR);
	if (session->public_sock)
		kernel_sock_shutdown(session->public_sock, SHUT_RDWR);
}

static void tcpcc_bridge_direction_done(struct tcpcc_bridge_session *session,
					int status)
{
	if (status)
		tcpcc_bridge_session_stop(session, status, true);
	if (atomic_inc_return(&session->directions_done) != 2)
		return;

	tcpcc_bridge_session_stop(session, 0, false);
	complete(&session->finished);
}

static int tcpcc_bridge_wait_host(struct tcpcc_bridge_session *session,
				  struct completion *ready, u32 *pending,
				  u32 wanted)
{
	for (;;) {
		unsigned long flags;
		u32 events;
		int status;
		bool stopping;

		wait_for_completion(ready);
		spin_lock_irqsave(&session->lock, flags);
		events = *pending;
		*pending = 0;
		status = session->status;
		stopping = session->stopping;
		spin_unlock_irqrestore(&session->lock, flags);

		if (status)
			return status;
		if (stopping)
			return -ECANCELED;
		if (events & (wanted | TCPCC_HOST_EVENT_HANGUP))
			return 0;
	}
}

static int tcpcc_bridge_public_to_backend_thread(void *arg)
{
	struct tcpcc_bridge_session *session = arg;
	int status = 0;

	wait_for_completion(&session->start);
	if (!READ_ONCE(session->running))
		return 0;

	while (!READ_ONCE(session->stopping)) {
		struct msghdr msg = { };
		struct kvec vec = {
			.iov_base = session->public_to_backend_buffer,
			.iov_len = TCPCC_BRIDGE_BUFFER_LIMIT,
		};
		size_t offset = 0;
		int received;

		received = kernel_recvmsg(session->public_sock, &msg, &vec, 1,
					  TCPCC_BRIDGE_BUFFER_LIMIT, 0);
		if (READ_ONCE(session->stopping))
			break;
		if (received < 0) {
			status = received;
			break;
		}
		if (!received) {
			status = tcpcc_host_shutdown(session->host_fd,
						     TCPCC_HOST_SHUT_WR);
			break;
		}

		while (offset < (size_t)received) {
			size_t remaining = (size_t)received - offset;
			ssize_t sent;

			sent = tcpcc_host_send_fd(
				session->host_fd,
				session->public_to_backend_buffer + offset,
				remaining);
			if (sent == -EAGAIN) {
				session->host_send_eagain++;
				status = tcpcc_bridge_wait_host(
					session, &session->host_writable,
					&session->write_events,
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
			if ((size_t)sent < remaining)
				session->host_partial_writes++;
			offset += sent;
			session->public_to_backend_bytes += sent;
		}
		if (status)
			break;
	}

	tcpcc_bridge_direction_done(session, status);
	return status;
}

static int tcpcc_bridge_send_public(struct tcpcc_bridge_session *session,
				    const u8 *buffer, size_t length)
{
	size_t offset = 0;

	while (offset < length) {
		struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
		struct kvec vec = {
			.iov_base = (void *)(buffer + offset),
			.iov_len = length - offset,
		};
		int sent;

		sent = kernel_sendmsg(session->public_sock, &msg, &vec, 1,
				      length - offset);
		if (sent < 0)
			return sent;
		if (!sent)
			return -EIO;
		offset += sent;
		session->backend_to_public_bytes += sent;
	}

	return 0;
}

static int tcpcc_bridge_backend_to_public_thread(void *arg)
{
	struct tcpcc_bridge_session *session = arg;
	bool host_ready = false;
	int status = 0;

	wait_for_completion(&session->start);
	if (!READ_ONCE(session->running))
		return 0;

	while (!READ_ONCE(session->stopping)) {
		ssize_t received;

		if (!host_ready) {
			status = tcpcc_bridge_wait_host(
				session, &session->host_readable,
				&session->read_events,
				TCPCC_HOST_EVENT_READABLE);
			if (status)
				break;
			host_ready = true;
		}

		received = tcpcc_host_recv_fd(
			session->host_fd, session->backend_to_public_buffer,
			TCPCC_BRIDGE_BUFFER_LIMIT);
		if (received == -EAGAIN) {
			session->host_recv_eagain++;
			host_ready = false;
			continue;
		}
		if (received < 0) {
			status = (int)received;
			break;
		}
		if (!received) {
			status = kernel_sock_shutdown(session->public_sock, SHUT_WR);
			break;
		}

		status = tcpcc_bridge_send_public(
			session, session->backend_to_public_buffer, received);
		if (status)
			break;
		/* Keep draining until EAGAIN so edge-triggered readiness is safe. */
	}

	tcpcc_bridge_direction_done(session, status);
	return status;
}

static void tcpcc_bridge_event_put(struct tcpcc_bridge_session *session)
{
	if (atomic_dec_and_test(&session->event_refs))
		complete(&session->event_idle);
}

static void tcpcc_bridge_dispatch_event(const struct tcpcc_host_event *event)
{
	struct tcpcc_bridge_session *session;
	unsigned long flags;
	unsigned int index;
	u32 runtime_slot;
	bool connecting;
	bool wake_read;
	bool wake_write;
	bool error;
	int host_fd;

	if (!(event->token & TCPCC_HOST_EVENT_RUNTIME_BIT))
		return;
	runtime_slot = (u32)event->token;
	if (runtime_slot < TCPCC_BRIDGE_RUNTIME_SLOT_BASE ||
	    runtime_slot >= TCPCC_BRIDGE_RUNTIME_SLOT_BASE +
			    TCPCC_BRIDGE_SESSION_LIMIT)
		return;

	index = runtime_slot - TCPCC_BRIDGE_RUNTIME_SLOT_BASE;
	session = &tcpcc_bridge_manager.sessions[index];
	spin_lock_irqsave(&session->lock, flags);
	if (!session->allocated || !session->accept_events ||
	    session->token != event->token) {
		spin_unlock_irqrestore(&session->lock, flags);
		return;
	}
	if (atomic_inc_return(&session->event_refs) == 1)
		reinit_completion(&session->event_idle);

	connecting = session->connecting;
	if (connecting) {
		session->connect_events |= event->events;
		session->terminal_events |= event->events &
			(TCPCC_HOST_EVENT_HANGUP | TCPCC_HOST_EVENT_ERROR);
		spin_unlock_irqrestore(&session->lock, flags);
		complete(&session->connect_ready);
		tcpcc_bridge_event_put(session);
		return;
	}

	error = event->events & TCPCC_HOST_EVENT_ERROR;
	wake_read = event->events & (TCPCC_HOST_EVENT_READABLE |
				       TCPCC_HOST_EVENT_HANGUP);
	wake_write = event->events & (TCPCC_HOST_EVENT_WRITABLE |
					TCPCC_HOST_EVENT_HANGUP);
	if (wake_read)
		session->read_events |= event->events;
	if (wake_write)
		session->write_events |= event->events;
	session->terminal_events |= event->events &
		(TCPCC_HOST_EVENT_HANGUP | TCPCC_HOST_EVENT_ERROR);
	host_fd = session->host_fd;
	spin_unlock_irqrestore(&session->lock, flags);

	if (error) {
		int status = tcpcc_host_socket_error(host_fd);

		tcpcc_bridge_session_stop(session, status ? status : -EIO, true);
	} else {
		if (wake_read)
			complete(&session->host_readable);
		if (wake_write)
			complete(&session->host_writable);
	}

	tcpcc_bridge_event_put(session);
}

static void tcpcc_bridge_abort_all(int status)
{
	unsigned int index;

	for (index = 0; index < TCPCC_BRIDGE_SESSION_LIMIT; index++) {
		struct tcpcc_bridge_session *session =
			&tcpcc_bridge_manager.sessions[index];
		unsigned long flags;
		bool allocated;
		bool connecting;

		spin_lock_irqsave(&session->lock, flags);
		allocated = session->allocated;
		connecting = session->connecting;
		if (allocated && connecting) {
			if (!session->status)
				session->status = status;
			session->stopping = true;
		}
		spin_unlock_irqrestore(&session->lock, flags);

		if (!allocated)
			continue;
		if (connecting) {
			complete_all(&session->connect_ready);
			complete_all(&session->host_readable);
			complete_all(&session->host_writable);
		} else {
			tcpcc_bridge_session_stop(session, status, true);
		}
	}
}

static int tcpcc_bridge_dispatcher_thread(void *unused)
{
	int status = 0;

	wait_for_completion(&tcpcc_bridge_manager.dispatcher_start);
	while (!kthread_should_stop() &&
	       !READ_ONCE(tcpcc_bridge_manager.dispatcher_stopping)) {
		struct tcpcc_host_event event;
		int ret;

		ret = tcpcc_host_runtime_event_wait_timeout(
			&event, msecs_to_jiffies(TCPCC_BRIDGE_EVENT_POLL_MS));
		if (ret == -ETIMEDOUT)
			continue;
		if (ret) {
			status = ret;
			WRITE_ONCE(tcpcc_bridge_manager.dispatcher_status, ret);
			tcpcc_bridge_abort_all(ret);
			break;
		}
		tcpcc_bridge_dispatch_event(&event);
	}

	WRITE_ONCE(tcpcc_bridge_manager.dispatcher_running, false);
	return status;
}

static int tcpcc_bridge_start_dispatcher(void)
{
	struct task_struct *task;
	int status;

	if (tcpcc_bridge_manager.dispatcher_task) {
		status = READ_ONCE(tcpcc_bridge_manager.dispatcher_status);
		return status;
	}

	tcpcc_bridge_manager.dispatcher_stopping = false;
	tcpcc_bridge_manager.dispatcher_status = 0;
	reinit_completion(&tcpcc_bridge_manager.dispatcher_start);
	task = kthread_run(tcpcc_bridge_dispatcher_thread, NULL,
			   "tcpcc-m8.2-disp");
	if (IS_ERR(task))
		return PTR_ERR(task);

	get_task_struct(task);
	tcpcc_bridge_manager.dispatcher_task = task;
	WRITE_ONCE(tcpcc_bridge_manager.dispatcher_running, true);
	complete_all(&tcpcc_bridge_manager.dispatcher_start);
	return 0;
}

static struct tcpcc_bridge_session *tcpcc_bridge_find_free(void)
{
	unsigned int index;

	for (index = 0; index < TCPCC_BRIDGE_SESSION_LIMIT; index++) {
		if (!READ_ONCE(tcpcc_bridge_manager.sessions[index].allocated))
			return &tcpcc_bridge_manager.sessions[index];
	}
	return NULL;
}

static struct tcpcc_bridge_session *tcpcc_bridge_find_handle(int handle)
{
	struct tcpcc_bridge_session *session;
	unsigned int index;
	u32 generation;
	u32 raw;
	u32 slot;

	if (handle <= 0)
		return NULL;
	raw = (u32)handle;
	slot = raw & TCPCC_BRIDGE_HANDLE_SLOT_MASK;
	generation = raw >> TCPCC_BRIDGE_HANDLE_SLOT_BITS;
	if (!slot || slot > TCPCC_BRIDGE_SESSION_LIMIT || !generation ||
	    generation > TCPCC_BRIDGE_HANDLE_GENERATION_MASK)
		return NULL;

	index = slot - 1U;
	session = &tcpcc_bridge_manager.sessions[index];
	if (!READ_ONCE(session->allocated) || session->handle != handle ||
	    session->generation != generation)
		return NULL;
	return session;
}

static void tcpcc_bridge_prepare_session(
				struct tcpcc_bridge_session *session,
				struct socket *public_sock)
{
	unsigned long flags;
	u32 generation = tcpcc_bridge_next_generation(session->generation);
	unsigned int index = session - tcpcc_bridge_manager.sessions;

	atomic_set(&session->directions_done, 0);
	atomic_set(&session->event_refs, 0);
	init_completion(&session->start);
	init_completion(&session->finished);
	init_completion(&session->connect_ready);
	init_completion(&session->host_readable);
	init_completion(&session->host_writable);
	init_completion(&session->event_idle);
	session->public_to_backend_task = NULL;
	session->backend_to_public_task = NULL;
	session->registered = false;

	spin_lock_irqsave(&session->lock, flags);
	session->public_sock = public_sock;
	session->host_fd = -1;
	session->generation = generation;
	session->index = index;
	session->handle = tcpcc_bridge_make_handle(index, generation);
	session->token = TCPCC_HOST_EVENT_RUNTIME_TOKEN(
		TCPCC_BRIDGE_RUNTIME_SLOT_BASE + index, generation);
	session->status = 0;
	session->connect_events = 0;
	session->read_events = 0;
	session->write_events = 0;
	session->terminal_events = 0;
	session->host_send_eagain = 0;
	session->host_partial_writes = 0;
	session->host_recv_eagain = 0;
	session->public_to_backend_bytes = 0;
	session->backend_to_public_bytes = 0;
	session->connecting = true;
	session->running = false;
	session->stopping = false;
	session->accept_events = true;
	session->allocated = true;
	spin_unlock_irqrestore(&session->lock, flags);

	tcpcc_bridge_manager.active_sessions++;
}

static int tcpcc_bridge_connect(struct tcpcc_bridge_session *session,
				__be32 address, __be16 port)
{
	unsigned long flags;
	u32 events;
	int status;
	int ret;

	ret = tcpcc_host_event_add_mask(session->host_fd, session->token,
					TCPCC_HOST_EVENT_WRITABLE, true);
	if (ret)
		return ret;
	session->registered = true;

	ret = tcpcc_host_tcp_connect(session->host_fd, address, port);
	if (ret && ret != -EINPROGRESS)
		return ret;

	if (!wait_for_completion_timeout(
			&session->connect_ready,
			msecs_to_jiffies(TCPCC_BRIDGE_CONNECT_TIMEOUT_MS)))
		return -ETIMEDOUT;

	spin_lock_irqsave(&session->lock, flags);
	events = session->connect_events;
	status = session->status;
	spin_unlock_irqrestore(&session->lock, flags);
	if (status)
		return status;
	if (!(events & (TCPCC_HOST_EVENT_WRITABLE |
			TCPCC_HOST_EVENT_ERROR)))
		return -EIO;

	ret = tcpcc_host_socket_error(session->host_fd);
	if (ret)
		return ret;
	if (!(events & TCPCC_HOST_EVENT_WRITABLE))
		return -EIO;
	return 0;
}

static void tcpcc_bridge_stop_task(struct task_struct **task)
{
	if (!*task)
		return;
	kthread_stop_put(*task);
	*task = NULL;
}

static void tcpcc_bridge_stop_setup_tasks(
				struct tcpcc_bridge_session *session)
{
	unsigned long flags;

	spin_lock_irqsave(&session->lock, flags);
	session->running = false;
	session->stopping = true;
	spin_unlock_irqrestore(&session->lock, flags);
	complete_all(&session->start);
	tcpcc_bridge_stop_task(&session->public_to_backend_task);
	tcpcc_bridge_stop_task(&session->backend_to_public_task);
}

static int tcpcc_bridge_disable_events(
				struct tcpcc_bridge_session *session)
{
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&session->lock, flags);
	session->accept_events = false;
	spin_unlock_irqrestore(&session->lock, flags);

	if (session->registered) {
		ret = tcpcc_host_event_del(session->host_fd);
		session->registered = false;
	}
	if (atomic_read(&session->event_refs))
		wait_for_completion(&session->event_idle);
	return ret;
}

static int tcpcc_bridge_close_host(struct tcpcc_bridge_session *session)
{
	int ret = 0;

	if (session->host_fd >= 0) {
		ret = tcpcc_host_close(session->host_fd);
		session->host_fd = -1;
	}
	return ret;
}

static void tcpcc_bridge_release_failed_start(
				struct tcpcc_bridge_session *session)
{
	unsigned long flags;

	spin_lock_irqsave(&session->lock, flags);
	session->public_sock = NULL;
	session->connecting = false;
	session->running = false;
	session->accept_events = false;
	session->allocated = false;
	spin_unlock_irqrestore(&session->lock, flags);
	tcpcc_bridge_manager.active_sessions--;
}

int tcpcc_bridge_start(struct socket *public_sock, __be32 backend_address,
		       __be16 backend_port, int *handle)
{
	struct tcpcc_bridge_session *session;
	unsigned long flags;
	int cleanup_ret;
	int ret;

	mutex_lock(&tcpcc_bridge_control_lock);
	tcpcc_bridge_manager_init();
	ret = tcpcc_bridge_start_dispatcher();
	if (ret)
		goto unlock;
	if (!READ_ONCE(tcpcc_bridge_manager.dispatcher_running)) {
		ret = READ_ONCE(tcpcc_bridge_manager.dispatcher_status);
		if (!ret)
			ret = -EIO;
		goto unlock;
	}

	session = tcpcc_bridge_find_free();
	if (!session) {
		ret = -ENOSPC;
		goto unlock;
	}
	tcpcc_bridge_prepare_session(session, public_sock);

	session->host_fd = tcpcc_host_tcp_socket();
	if (session->host_fd < 0) {
		ret = session->host_fd;
		goto fail;
	}
	ret = tcpcc_host_set_socket_buffers(
		session->host_fd,
		TCPCC_BRIDGE_HOST_SOCKET_BUFFER_REQUEST,
		TCPCC_BRIDGE_HOST_SOCKET_BUFFER_REQUEST);
	if (ret)
		goto fail;
	ret = tcpcc_bridge_connect(session, backend_address, backend_port);
	if (ret)
		goto fail;

	session->public_to_backend_task = kthread_run(
		tcpcc_bridge_public_to_backend_thread, session,
		"tcpcc-p2b/%u", session->index);
	if (IS_ERR(session->public_to_backend_task)) {
		ret = PTR_ERR(session->public_to_backend_task);
		session->public_to_backend_task = NULL;
		goto fail;
	}
	get_task_struct(session->public_to_backend_task);
	session->backend_to_public_task = kthread_run(
		tcpcc_bridge_backend_to_public_thread, session,
		"tcpcc-b2p/%u", session->index);
	if (IS_ERR(session->backend_to_public_task)) {
		ret = PTR_ERR(session->backend_to_public_task);
		session->backend_to_public_task = NULL;
		goto fail;
	}
	get_task_struct(session->backend_to_public_task);

	spin_lock_irqsave(&session->lock, flags);
	session->connecting = false;
	spin_unlock_irqrestore(&session->lock, flags);
	ret = tcpcc_host_event_mod_mask(
		session->host_fd, session->token,
		TCPCC_HOST_EVENT_READABLE | TCPCC_HOST_EVENT_WRITABLE, true);
	if (ret)
		goto fail;

	WRITE_ONCE(session->running, true);
	*handle = session->handle;
	complete_all(&session->start);
	mutex_unlock(&tcpcc_bridge_control_lock);
	return 0;

fail:
	tcpcc_bridge_stop_setup_tasks(session);
	cleanup_ret = tcpcc_bridge_disable_events(session);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	cleanup_ret = tcpcc_bridge_close_host(session);
	if (!ret && cleanup_ret)
		ret = cleanup_ret;
	tcpcc_bridge_release_failed_start(session);
unlock:
	mutex_unlock(&tcpcc_bridge_control_lock);
	return ret;
}

static int tcpcc_bridge_reap(struct tcpcc_bridge_session *session,
			     struct tcpcc_bridge_result *result)
{
	struct socket *public_sock;
	unsigned long flags;
	int cleanup_status;
	int close_status;
	int status;

	cleanup_status = tcpcc_bridge_disable_events(session);
	tcpcc_bridge_stop_task(&session->public_to_backend_task);
	tcpcc_bridge_stop_task(&session->backend_to_public_task);
	close_status = tcpcc_bridge_close_host(session);
	if (!cleanup_status && close_status)
		cleanup_status = close_status;

	public_sock = session->public_sock;
	if (public_sock) {
		kernel_sock_shutdown(public_sock, SHUT_RDWR);
		sock_release(public_sock);
	}

	status = session->status ? session->status : cleanup_status;
	if (result) {
		memset(result, 0, sizeof(*result));
		result->token = session->token;
		result->public_to_backend_bytes =
			session->public_to_backend_bytes;
		result->backend_to_public_bytes =
			session->backend_to_public_bytes;
		result->buffer_limit = TCPCC_BRIDGE_BUFFER_LIMIT;
		result->total_buffer_limit = TCPCC_BRIDGE_TOTAL_BUFFER_LIMIT;
		result->terminal_events = session->terminal_events;
		result->host_send_eagain = session->host_send_eagain;
		result->host_partial_writes = session->host_partial_writes;
		result->host_recv_eagain = session->host_recv_eagain;
		result->session_limit = TCPCC_BRIDGE_SESSION_LIMIT;
		result->status = status;
	}

	spin_lock_irqsave(&session->lock, flags);
	session->public_sock = NULL;
	session->connecting = false;
	session->running = false;
	session->accept_events = false;
	session->allocated = false;
	spin_unlock_irqrestore(&session->lock, flags);
	tcpcc_bridge_manager.active_sessions--;
	return status;
}

static int tcpcc_bridge_join_common(int handle, unsigned long timeout,
				    struct tcpcc_bridge_result *result,
				    bool return_session_status)
{
	struct tcpcc_bridge_session *session;
	int session_status;
	int ret;

	mutex_lock(&tcpcc_bridge_control_lock);
	session = tcpcc_bridge_find_handle(handle);
	if (!session) {
		ret = -ENOENT;
		goto unlock;
	}
	if (!wait_for_completion_timeout(&session->finished, timeout)) {
		ret = -ETIMEDOUT;
		goto unlock;
	}

	session_status = tcpcc_bridge_reap(session, result);
	ret = return_session_status ? session_status : 0;
unlock:
	mutex_unlock(&tcpcc_bridge_control_lock);
	return ret;
}

int tcpcc_bridge_join(int handle, unsigned long timeout,
		      struct tcpcc_bridge_result *result)
{
	return tcpcc_bridge_join_common(handle, timeout, result, true);
}

int tcpcc_bridge_join_result(int handle, unsigned long timeout,
			     struct tcpcc_bridge_result *result)
{
	return tcpcc_bridge_join_common(handle, timeout, result, false);
}

int tcpcc_bridge_cancel_session(int handle)
{
	struct tcpcc_bridge_session *session;
	int ret = 0;

	mutex_lock(&tcpcc_bridge_control_lock);
	session = tcpcc_bridge_find_handle(handle);
	if (!session) {
		ret = -ENOENT;
		goto unlock;
	}

	tcpcc_bridge_session_stop(session, -ECANCELED, true);
unlock:
	mutex_unlock(&tcpcc_bridge_control_lock);
	return ret;
}

bool tcpcc_bridge_active(void)
{
	bool active;

	mutex_lock(&tcpcc_bridge_control_lock);
	active = tcpcc_bridge_manager.dispatcher_task != NULL;
	mutex_unlock(&tcpcc_bridge_control_lock);
	return active;
}

void tcpcc_bridge_cancel(void)
{
	unsigned int index;

	mutex_lock(&tcpcc_bridge_control_lock);
	if (!tcpcc_bridge_manager.initialized)
		goto unlock;

	for (index = 0; index < TCPCC_BRIDGE_SESSION_LIMIT; index++) {
		struct tcpcc_bridge_session *session =
			&tcpcc_bridge_manager.sessions[index];

		if (READ_ONCE(session->allocated))
			tcpcc_bridge_session_stop(session, -ECANCELED, true);
	}
	for (index = 0; index < TCPCC_BRIDGE_SESSION_LIMIT; index++) {
		struct tcpcc_bridge_session *session =
			&tcpcc_bridge_manager.sessions[index];

		if (!READ_ONCE(session->allocated))
			continue;
		wait_for_completion(&session->finished);
		tcpcc_bridge_reap(session, NULL);
	}

	if (tcpcc_bridge_manager.dispatcher_task) {
		WRITE_ONCE(tcpcc_bridge_manager.dispatcher_stopping, true);
		kthread_stop_put(tcpcc_bridge_manager.dispatcher_task);
		tcpcc_bridge_manager.dispatcher_task = NULL;
		WRITE_ONCE(tcpcc_bridge_manager.dispatcher_running, false);
	}
unlock:
	mutex_unlock(&tcpcc_bridge_control_lock);
}

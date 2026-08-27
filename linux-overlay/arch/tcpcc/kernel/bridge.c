// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/idr.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/printk.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uio.h>
#include <linux/wait.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <asm/bridge.h>
#include <asm/host.h>

#define TCPCC_BRIDGE_CONNECT_TIMEOUT_MS 3000
#define TCPCC_BRIDGE_DIRECTION_BUDGET  32U
#define TCPCC_BRIDGE_DISPATCH_BUDGET   64U

struct tcpcc_bridge_session;

struct tcpcc_bridge_slot {
	struct list_head free_node;
	struct tcpcc_bridge_session *session;
	u32 id;
	u32 generation;
};

struct tcpcc_bridge_session {
	struct list_head active_node;
	struct list_head ready_node;
	struct list_head retired_node;
	struct list_head buffer_wait_node;
	spinlock_t lock;
	struct tcpcc_bridge_slot *slot;
	struct socket *public_sock;
	int host_fd;
	int handle;
	u64 token;
	u32 generation;
	bool allocated;
	bool ready_queued;
	bool buffer_wait_queued;
	bool public_buffer_waiting;
	bool backend_buffer_waiting;
	bool accept_events;
	bool registered;
	bool connecting;
	bool running;
	bool stopping;
	bool finished_notified;
	bool public_callbacks_installed;
	bool public_readable;
	bool public_writable;
	bool host_readable;
	bool host_writable;
	bool public_to_backend_done;
	bool backend_to_public_done;
	int status;
	u32 connect_events;
	u32 terminal_events;
	u32 host_send_eagain;
	u32 host_partial_writes;
	u32 host_recv_eagain;
	u64 public_to_backend_bytes;
	u64 backend_to_public_bytes;
	size_t public_to_backend_offset;
	size_t public_to_backend_length;
	size_t backend_to_public_offset;
	size_t backend_to_public_length;
	atomic_t event_refs;
	struct completion finished;
	struct completion connect_ready;
	struct completion event_idle;
	void (*saved_data_ready)(struct sock *sk);
	void (*saved_write_space)(struct sock *sk);
	void (*saved_state_change)(struct sock *sk);
	void (*saved_error_report)(struct sock *sk);
	u8 *public_to_backend_buffer;
	u8 *backend_to_public_buffer;
};

struct tcpcc_bridge_manager {
	bool initialized;
	bool dispatcher_running;
	bool dispatcher_stopping;
	int dispatcher_status;
	unsigned int active_sessions;
	u32 buffer_bytes;
	u32 buffer_high_water;
	spinlock_t registry_lock;
	spinlock_t ready_lock;
	struct idr slots;
	struct list_head free_slots;
	struct list_head active;
	struct list_head ready;
	struct list_head retired;
	struct list_head buffer_waiters;
	wait_queue_head_t dispatcher_wait;
	atomic_t dispatcher_pending;
	struct task_struct *dispatcher_task;
	void (*completion_notify)(void *);
	void *completion_notify_data;
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
	if (tcpcc_bridge_manager.initialized)
		return;

	spin_lock_init(&tcpcc_bridge_manager.registry_lock);
	spin_lock_init(&tcpcc_bridge_manager.ready_lock);
	idr_init(&tcpcc_bridge_manager.slots);
	INIT_LIST_HEAD(&tcpcc_bridge_manager.free_slots);
	INIT_LIST_HEAD(&tcpcc_bridge_manager.active);
	INIT_LIST_HEAD(&tcpcc_bridge_manager.ready);
	INIT_LIST_HEAD(&tcpcc_bridge_manager.retired);
	INIT_LIST_HEAD(&tcpcc_bridge_manager.buffer_waiters);
	init_waitqueue_head(&tcpcc_bridge_manager.dispatcher_wait);
	atomic_set(&tcpcc_bridge_manager.dispatcher_pending, 0);
	tcpcc_bridge_manager.initialized = true;
}

static void tcpcc_bridge_dispatcher_wake(void *unused)
{
	atomic_set(&tcpcc_bridge_manager.dispatcher_pending, 1);
	wake_up(&tcpcc_bridge_manager.dispatcher_wait);
}

static void tcpcc_bridge_queue_session(struct tcpcc_bridge_session *session)
{
	unsigned long flags;

	spin_lock_irqsave(&tcpcc_bridge_manager.ready_lock, flags);
	if (READ_ONCE(session->allocated) && !session->ready_queued) {
		list_add_tail(&session->ready_node, &tcpcc_bridge_manager.ready);
		session->ready_queued = true;
	}
	spin_unlock_irqrestore(&tcpcc_bridge_manager.ready_lock, flags);
	tcpcc_bridge_dispatcher_wake(NULL);
}

static struct tcpcc_bridge_session *tcpcc_bridge_take_ready(void)
{
	struct tcpcc_bridge_session *session = NULL;
	unsigned long flags;

	spin_lock_irqsave(&tcpcc_bridge_manager.ready_lock, flags);
	if (!list_empty(&tcpcc_bridge_manager.ready)) {
		session = list_first_entry(&tcpcc_bridge_manager.ready,
					   struct tcpcc_bridge_session,
					   ready_node);
		list_del_init(&session->ready_node);
		session->ready_queued = false;
	}
	spin_unlock_irqrestore(&tcpcc_bridge_manager.ready_lock, flags);
	return session;
}

static void tcpcc_bridge_unqueue_session(struct tcpcc_bridge_session *session)
{
	unsigned long flags;

	spin_lock_irqsave(&tcpcc_bridge_manager.ready_lock, flags);
	if (session->ready_queued) {
		list_del_init(&session->ready_node);
		session->ready_queued = false;
	}
	spin_unlock_irqrestore(&tcpcc_bridge_manager.ready_lock, flags);
}

static int tcpcc_bridge_acquire_buffer(u8 **buffer)
{
	u8 *allocated;

	if (*buffer)
		return 0;
	if (tcpcc_bridge_manager.buffer_bytes + TCPCC_BRIDGE_BUFFER_LIMIT >
	    TCPCC_BRIDGE_TOTAL_BUFFER_LIMIT)
		return -EAGAIN;
	allocated = kmalloc(TCPCC_BRIDGE_BUFFER_LIMIT, GFP_KERNEL);
	if (!allocated)
		return -ENOMEM;
	*buffer = allocated;
	tcpcc_bridge_manager.buffer_bytes += TCPCC_BRIDGE_BUFFER_LIMIT;
	if (tcpcc_bridge_manager.buffer_bytes >
	    tcpcc_bridge_manager.buffer_high_water)
		tcpcc_bridge_manager.buffer_high_water =
			tcpcc_bridge_manager.buffer_bytes;
	return 0;
}

static void tcpcc_bridge_wait_for_buffer(
				struct tcpcc_bridge_session *session,
				bool public_to_backend)
{
	if (public_to_backend)
		session->public_buffer_waiting = true;
	else
		session->backend_buffer_waiting = true;
	if (!session->buffer_wait_queued) {
		list_add_tail(&session->buffer_wait_node,
			      &tcpcc_bridge_manager.buffer_waiters);
		session->buffer_wait_queued = true;
	}
}

static void tcpcc_bridge_wake_buffer_waiters(void)
{
	struct tcpcc_bridge_session *session;
	struct tcpcc_bridge_session *next;

	list_for_each_entry_safe(session, next,
				 &tcpcc_bridge_manager.buffer_waiters,
				 buffer_wait_node) {
		list_del_init(&session->buffer_wait_node);
		session->buffer_wait_queued = false;
		session->public_buffer_waiting = false;
		session->backend_buffer_waiting = false;
		tcpcc_bridge_queue_session(session);
	}
}

static void tcpcc_bridge_release_buffer(u8 **buffer)
{
	if (!*buffer)
		return;
	kfree(*buffer);
	*buffer = NULL;
	tcpcc_bridge_manager.buffer_bytes -= TCPCC_BRIDGE_BUFFER_LIMIT;
	tcpcc_bridge_wake_buffer_waiters();
}

static void tcpcc_bridge_release_session_buffers(
				struct tcpcc_bridge_session *session)
{
	if (session->buffer_wait_queued) {
		list_del_init(&session->buffer_wait_node);
		session->buffer_wait_queued = false;
	}
	session->public_buffer_waiting = false;
	session->backend_buffer_waiting = false;
	tcpcc_bridge_release_buffer(&session->public_to_backend_buffer);
	tcpcc_bridge_release_buffer(&session->backend_to_public_buffer);
}

static void tcpcc_bridge_mark_public_ready(
				struct tcpcc_bridge_session *session,
				bool readable, bool writable)
{
	unsigned long flags;
	bool allocated;

	spin_lock_irqsave(&session->lock, flags);
	allocated = session->allocated;
	if (allocated) {
		if (readable)
			session->public_readable = true;
		if (writable)
			session->public_writable = true;
	}
	spin_unlock_irqrestore(&session->lock, flags);
	if (allocated)
		tcpcc_bridge_queue_session(session);
}

static void tcpcc_bridge_public_data_ready(struct sock *sk)
{
	struct tcpcc_bridge_session *session;
	void (*saved_data_ready)(struct sock *sk) = NULL;

	read_lock_bh(&sk->sk_callback_lock);
	session = sk->sk_user_data;
	if (session && session->public_sock &&
	    session->public_sock->sk == sk) {
		saved_data_ready = session->saved_data_ready;
		tcpcc_bridge_mark_public_ready(session, true, false);
	}
	if (saved_data_ready)
		saved_data_ready(sk);
	read_unlock_bh(&sk->sk_callback_lock);
}

static void tcpcc_bridge_public_write_space(struct sock *sk)
{
	struct tcpcc_bridge_session *session;
	void (*saved_write_space)(struct sock *sk) = NULL;

	read_lock_bh(&sk->sk_callback_lock);
	session = sk->sk_user_data;
	if (session && session->public_sock &&
	    session->public_sock->sk == sk) {
		saved_write_space = session->saved_write_space;
		tcpcc_bridge_mark_public_ready(session, false, true);
	}
	if (saved_write_space)
		saved_write_space(sk);
	read_unlock_bh(&sk->sk_callback_lock);
}

static void tcpcc_bridge_public_state_change(struct sock *sk)
{
	struct tcpcc_bridge_session *session;
	void (*saved_state_change)(struct sock *sk) = NULL;

	read_lock_bh(&sk->sk_callback_lock);
	session = sk->sk_user_data;
	if (session && session->public_sock &&
	    session->public_sock->sk == sk) {
		saved_state_change = session->saved_state_change;
		tcpcc_bridge_mark_public_ready(session, true, true);
	}
	if (saved_state_change)
		saved_state_change(sk);
	read_unlock_bh(&sk->sk_callback_lock);
}

static void tcpcc_bridge_public_error_report(struct sock *sk)
{
	struct tcpcc_bridge_session *session;
	void (*saved_error_report)(struct sock *sk) = NULL;

	read_lock_bh(&sk->sk_callback_lock);
	session = sk->sk_user_data;
	if (session && session->public_sock &&
	    session->public_sock->sk == sk) {
		saved_error_report = session->saved_error_report;
		tcpcc_bridge_mark_public_ready(session, true, true);
	}
	if (saved_error_report)
		saved_error_report(sk);
	read_unlock_bh(&sk->sk_callback_lock);
}

static int tcpcc_bridge_install_public_callbacks(
				struct tcpcc_bridge_session *session)
{
	struct sock *sk = session->public_sock->sk;
	int ret = 0;

	write_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_user_data) {
		ret = -EBUSY;
		goto unlock;
	}
	session->saved_data_ready = sk->sk_data_ready;
	session->saved_write_space = sk->sk_write_space;
	session->saved_state_change = sk->sk_state_change;
	session->saved_error_report = sk->sk_error_report;
	sk->sk_user_data = session;
	WRITE_ONCE(sk->sk_data_ready, tcpcc_bridge_public_data_ready);
	WRITE_ONCE(sk->sk_write_space, tcpcc_bridge_public_write_space);
	WRITE_ONCE(sk->sk_state_change, tcpcc_bridge_public_state_change);
	WRITE_ONCE(sk->sk_error_report, tcpcc_bridge_public_error_report);
	session->public_callbacks_installed = true;
unlock:
	write_unlock_bh(&sk->sk_callback_lock);
	return ret;
}

static void tcpcc_bridge_restore_public_callbacks(
				struct tcpcc_bridge_session *session)
{
	struct socket *public_sock = session->public_sock;
	struct sock *sk;

	if (!public_sock || !session->public_callbacks_installed)
		return;
	sk = public_sock->sk;
	write_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_user_data == session) {
		sk->sk_user_data = NULL;
		WRITE_ONCE(sk->sk_data_ready, session->saved_data_ready);
		WRITE_ONCE(sk->sk_write_space, session->saved_write_space);
		WRITE_ONCE(sk->sk_state_change, session->saved_state_change);
		WRITE_ONCE(sk->sk_error_report, session->saved_error_report);
	}
	session->public_callbacks_installed = false;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void tcpcc_bridge_session_stop(struct tcpcc_bridge_session *session,
				      int status, bool abort_sockets)
{
	unsigned long flags;
	bool first = false;
	bool connecting = false;

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
	connecting = session->connecting;
	spin_unlock_irqrestore(&session->lock, flags);

	complete_all(&session->connect_ready);
	if (!connecting)
		tcpcc_bridge_queue_session(session);
	if (!first || !abort_sockets)
		return;

	if (session->host_fd >= 0)
		tcpcc_host_shutdown(session->host_fd, TCPCC_HOST_SHUT_RDWR);
	if (session->public_sock)
		kernel_sock_shutdown(session->public_sock, SHUT_RDWR);
}

static void tcpcc_bridge_session_finish(struct tcpcc_bridge_session *session)
{
	void (*notify)(void *);
	void *notify_data;
	unsigned long flags;
	bool finished = false;

	spin_lock_irqsave(&session->lock, flags);
	if (session->allocated && !session->finished_notified) {
		session->running = false;
		session->stopping = true;
		session->finished_notified = true;
		finished = true;
	}
	spin_unlock_irqrestore(&session->lock, flags);
	if (!finished)
		return;

	tcpcc_bridge_release_session_buffers(session);
	complete(&session->finished);
	notify = smp_load_acquire(&tcpcc_bridge_manager.completion_notify);
	if (notify) {
		notify_data = READ_ONCE(
			tcpcc_bridge_manager.completion_notify_data);
		notify(notify_data);
	}
}

static bool tcpcc_bridge_take_readable(
				struct tcpcc_bridge_session *session,
				bool public_side)
{
	unsigned long flags;
	bool ready;

	spin_lock_irqsave(&session->lock, flags);
	ready = public_side ? session->public_readable :
			      session->host_readable;
	if (public_side)
		session->public_readable = false;
	else
		session->host_readable = false;
	spin_unlock_irqrestore(&session->lock, flags);
	return ready;
}

static bool tcpcc_bridge_take_writable(
				struct tcpcc_bridge_session *session,
				bool public_side)
{
	unsigned long flags;
	bool ready;

	spin_lock_irqsave(&session->lock, flags);
	ready = public_side ? session->public_writable :
			      session->host_writable;
	if (public_side)
		session->public_writable = false;
	else
		session->host_writable = false;
	spin_unlock_irqrestore(&session->lock, flags);
	return ready;
}

static void tcpcc_bridge_set_readable(
				struct tcpcc_bridge_session *session,
				bool public_side)
{
	unsigned long flags;

	spin_lock_irqsave(&session->lock, flags);
	if (public_side)
		session->public_readable = true;
	else
		session->host_readable = true;
	spin_unlock_irqrestore(&session->lock, flags);
}

static void tcpcc_bridge_set_writable(
				struct tcpcc_bridge_session *session,
				bool public_side)
{
	unsigned long flags;

	spin_lock_irqsave(&session->lock, flags);
	if (public_side)
		session->public_writable = true;
	else
		session->host_writable = true;
	spin_unlock_irqrestore(&session->lock, flags);
}

static int tcpcc_bridge_pump_public_to_backend(
				struct tcpcc_bridge_session *session)
{
	unsigned int operations = 0;

	while (operations < TCPCC_BRIDGE_DIRECTION_BUDGET &&
	       !session->public_to_backend_done) {
		if (session->public_to_backend_offset <
		    session->public_to_backend_length) {
			size_t remaining = session->public_to_backend_length -
					   session->public_to_backend_offset;
			ssize_t sent;

			if (!tcpcc_bridge_take_writable(session, false))
				break;
			sent = tcpcc_host_send_fd(
				session->host_fd,
				session->public_to_backend_buffer +
					session->public_to_backend_offset,
				remaining);
			operations++;
			if (sent == -EAGAIN) {
				session->host_send_eagain++;
				break;
			}
			if (sent < 0)
				return (int)sent;
			if (!sent)
				return -EIO;
			if ((size_t)sent < remaining)
				session->host_partial_writes++;
			tcpcc_bridge_set_writable(session, false);
			session->public_to_backend_offset += sent;
			session->public_to_backend_bytes += sent;
			if (session->public_to_backend_offset ==
			    session->public_to_backend_length) {
				session->public_to_backend_offset = 0;
				session->public_to_backend_length = 0;
			}
			continue;
		}

		if (session->public_buffer_waiting)
			break;
		if (!tcpcc_bridge_take_readable(session, true))
			break;
		{
			struct msghdr msg = { };
			struct kvec vec;
			int received;
			int ret;

			ret = tcpcc_bridge_acquire_buffer(
				&session->public_to_backend_buffer);
			if (ret == -EAGAIN) {
				tcpcc_bridge_set_readable(session, true);
				tcpcc_bridge_wait_for_buffer(session, true);
				break;
			}
			if (ret)
				return ret;
			vec.iov_base = session->public_to_backend_buffer;
			vec.iov_len = TCPCC_BRIDGE_BUFFER_LIMIT;

			received = kernel_recvmsg(
				session->public_sock, &msg, &vec, 1,
				TCPCC_BRIDGE_BUFFER_LIMIT, MSG_DONTWAIT);
			operations++;
			if (received == -EAGAIN) {
				tcpcc_bridge_release_buffer(
					&session->public_to_backend_buffer);
				break;
			}
			if (received < 0)
				return received;
			if (!received) {
				tcpcc_bridge_release_buffer(
					&session->public_to_backend_buffer);
				ret = tcpcc_host_shutdown(
					session->host_fd, TCPCC_HOST_SHUT_WR);

				if (ret)
					return ret;
				session->public_to_backend_done = true;
				break;
			}
			tcpcc_bridge_set_readable(session, true);
			session->public_to_backend_length = received;
		}
	}

	if (operations == TCPCC_BRIDGE_DIRECTION_BUDGET)
		tcpcc_bridge_queue_session(session);
	return 0;
}

static int tcpcc_bridge_pump_backend_to_public(
				struct tcpcc_bridge_session *session)
{
	unsigned int operations = 0;

	while (operations < TCPCC_BRIDGE_DIRECTION_BUDGET &&
	       !session->backend_to_public_done) {
		if (session->backend_to_public_offset <
		    session->backend_to_public_length) {
			struct msghdr msg = {
				.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
			};
			struct kvec vec = {
				.iov_base = session->backend_to_public_buffer +
					session->backend_to_public_offset,
				.iov_len = session->backend_to_public_length -
					session->backend_to_public_offset,
			};
			int sent;

			if (!tcpcc_bridge_take_writable(session, true))
				break;
			sent = kernel_sendmsg(session->public_sock, &msg, &vec, 1,
					      vec.iov_len);
			operations++;
			if (sent == -EAGAIN) {
				break;
			}
			if (sent < 0)
				return sent;
			if (!sent)
				return -EIO;
			tcpcc_bridge_set_writable(session, true);
			session->backend_to_public_offset += sent;
			session->backend_to_public_bytes += sent;
			if (session->backend_to_public_offset ==
			    session->backend_to_public_length) {
				session->backend_to_public_offset = 0;
				session->backend_to_public_length = 0;
			}
			continue;
		}

		if (session->backend_buffer_waiting)
			break;
		if (!tcpcc_bridge_take_readable(session, false))
			break;
		{
			ssize_t received;
			int ret;

			ret = tcpcc_bridge_acquire_buffer(
				&session->backend_to_public_buffer);
			if (ret == -EAGAIN) {
				tcpcc_bridge_set_readable(session, false);
				tcpcc_bridge_wait_for_buffer(session, false);
				break;
			}
			if (ret)
				return ret;

			received = tcpcc_host_recv_fd(
				session->host_fd,
				session->backend_to_public_buffer,
				TCPCC_BRIDGE_BUFFER_LIMIT);
			operations++;
			if (received == -EAGAIN) {
				session->host_recv_eagain++;
				tcpcc_bridge_release_buffer(
					&session->backend_to_public_buffer);
				break;
			}
			if (received < 0)
				return (int)received;
			if (!received) {
				tcpcc_bridge_release_buffer(
					&session->backend_to_public_buffer);
				ret = kernel_sock_shutdown(session->public_sock,
						   SHUT_WR);

				if (ret)
					return ret;
				session->backend_to_public_done = true;
				break;
			}
			tcpcc_bridge_set_readable(session, false);
			session->backend_to_public_length = received;
		}
	}

	if (operations == TCPCC_BRIDGE_DIRECTION_BUDGET)
		tcpcc_bridge_queue_session(session);
	return 0;
}

static void tcpcc_bridge_pump_session(struct tcpcc_bridge_session *session)
{
	unsigned long flags;
	bool allocated;
	bool running;
	bool stopping;
	int status;

	spin_lock_irqsave(&session->lock, flags);
	allocated = session->allocated;
	running = session->running;
	stopping = session->stopping;
	spin_unlock_irqrestore(&session->lock, flags);
	if (!allocated || (!running && !stopping))
		return;
	if (stopping) {
		tcpcc_bridge_session_finish(session);
		return;
	}

	status = tcpcc_bridge_pump_public_to_backend(session);
	if (!status)
		status = tcpcc_bridge_pump_backend_to_public(session);
	if (status) {
		tcpcc_bridge_session_stop(session, status, true);
		tcpcc_bridge_session_finish(session);
		return;
	}
	/*
	 * Both forwarding directions can reach EOF before the FIN generated by
	 * kernel_sock_shutdown(SHUT_WR) has crossed the TUN and been acknowledged.
	 * Keep the runtime alive until the accepted socket completes LAST_ACK;
	 * sk_state_change wakes the dispatcher for that final transition.
	 */
	if (session->public_to_backend_done &&
	    session->backend_to_public_done &&
	    READ_ONCE(session->public_sock->sk->sk_state) == TCP_CLOSE)
		tcpcc_bridge_session_finish(session);
}

static void tcpcc_bridge_event_put(struct tcpcc_bridge_session *session)
{
	if (atomic_dec_and_test(&session->event_refs))
		complete(&session->event_idle);
}

static void tcpcc_bridge_dispatch_event(const struct tcpcc_host_event *event)
{
	struct tcpcc_bridge_slot *slot;
	struct tcpcc_bridge_session *session;
	unsigned long flags;
	u32 runtime_slot;
	bool connecting;
	bool error;
	int host_fd;

	if (!(event->token & TCPCC_HOST_EVENT_RUNTIME_BIT))
		return;
	runtime_slot = (u32)event->token;
	if (runtime_slot < TCPCC_BRIDGE_RUNTIME_SLOT_BASE ||
	    runtime_slot >= TCPCC_BRIDGE_RUNTIME_SLOT_BASE +
			    TCPCC_BRIDGE_SESSION_LIMIT)
		return;

	spin_lock_irqsave(&tcpcc_bridge_manager.registry_lock, flags);
	slot = idr_find(&tcpcc_bridge_manager.slots,
			runtime_slot - TCPCC_BRIDGE_RUNTIME_SLOT_BASE + 1U);
	session = slot ? slot->session : NULL;
	if (!session || session->token != event->token) {
		spin_unlock_irqrestore(&tcpcc_bridge_manager.registry_lock, flags);
		return;
	}
	spin_lock(&session->lock);
	spin_unlock(&tcpcc_bridge_manager.registry_lock);
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
	if (event->events & (TCPCC_HOST_EVENT_READABLE |
			     TCPCC_HOST_EVENT_HANGUP))
		session->host_readable = true;
	if (event->events & (TCPCC_HOST_EVENT_WRITABLE |
			     TCPCC_HOST_EVENT_HANGUP))
		session->host_writable = true;
	session->terminal_events |= event->events &
		(TCPCC_HOST_EVENT_HANGUP | TCPCC_HOST_EVENT_ERROR);
	host_fd = session->host_fd;
	spin_unlock_irqrestore(&session->lock, flags);

	if (error) {
		int status = tcpcc_host_socket_error(host_fd);

		tcpcc_bridge_session_stop(session, status ? status : -EIO, true);
	}
	tcpcc_bridge_queue_session(session);
	tcpcc_bridge_event_put(session);
}

static void tcpcc_bridge_abort_all(int status)
{
	int id = 0;

	for (;;) {
		struct tcpcc_bridge_session *session = NULL;
		struct tcpcc_bridge_slot *slot;
		unsigned long flags;
		bool connecting = false;

		spin_lock_irqsave(&tcpcc_bridge_manager.registry_lock, flags);
		slot = idr_get_next(&tcpcc_bridge_manager.slots, &id);
		if (slot) {
			session = slot->session;
			if (session)
				connecting = READ_ONCE(session->connecting);
			id++;
		}
		spin_unlock_irqrestore(&tcpcc_bridge_manager.registry_lock, flags);
		if (!slot)
			break;
		if (session) {
			tcpcc_bridge_session_stop(session, status, true);
			if (!connecting)
				tcpcc_bridge_session_finish(session);
		}
	}
}

static int tcpcc_bridge_drain_host_events(void)
{
	for (;;) {
		struct tcpcc_host_event event;
		int ret;

		ret = tcpcc_host_runtime_event_poll(&event);
		if (ret == -EAGAIN)
			return 0;
		if (ret)
			return ret;
		tcpcc_bridge_dispatch_event(&event);
	}
}

static void tcpcc_bridge_drain_retired(void)
{
	struct tcpcc_bridge_session *session;
	struct tcpcc_bridge_session *next;
	unsigned long flags;
	LIST_HEAD(retired);

	spin_lock_irqsave(&tcpcc_bridge_manager.ready_lock, flags);
	list_splice_init(&tcpcc_bridge_manager.retired, &retired);
	spin_unlock_irqrestore(&tcpcc_bridge_manager.ready_lock, flags);
	list_for_each_entry_safe(session, next, &retired, retired_node) {
		list_del(&session->retired_node);
		kfree(session);
	}
}

static int tcpcc_bridge_dispatcher_thread(void *unused)
{
	int status = 0;

	for (;;) {
		unsigned int dispatched = 0;
		struct tcpcc_bridge_session *session;

		wait_event(tcpcc_bridge_manager.dispatcher_wait,
			   atomic_xchg(&tcpcc_bridge_manager.dispatcher_pending,
				       0) ||
			   kthread_should_stop() ||
			   READ_ONCE(tcpcc_bridge_manager.dispatcher_stopping));
		if (kthread_should_stop() ||
		    READ_ONCE(tcpcc_bridge_manager.dispatcher_stopping))
			break;
		tcpcc_bridge_drain_retired();

		status = tcpcc_bridge_drain_host_events();
		if (status) {
			WRITE_ONCE(tcpcc_bridge_manager.dispatcher_status,
				   status);
			tcpcc_bridge_abort_all(status);
			break;
		}
		while (dispatched < TCPCC_BRIDGE_DISPATCH_BUDGET &&
		       (session = tcpcc_bridge_take_ready()) != NULL) {
			tcpcc_bridge_pump_session(session);
			dispatched++;
		}
		if (dispatched == TCPCC_BRIDGE_DISPATCH_BUDGET)
			tcpcc_bridge_dispatcher_wake(NULL);
	}

	tcpcc_bridge_drain_retired();
	pr_notice("tcpcc: M9.4 bridge buffer high-water %u/%u bytes, current %u\n",
		  tcpcc_bridge_manager.buffer_high_water,
		  TCPCC_BRIDGE_TOTAL_BUFFER_LIMIT,
		  tcpcc_bridge_manager.buffer_bytes);
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
	atomic_set(&tcpcc_bridge_manager.dispatcher_pending, 0);
	status = tcpcc_host_runtime_event_set_notifier(
		tcpcc_bridge_dispatcher_wake, &tcpcc_bridge_manager);
	if (status)
		return status;

	task = kthread_run(tcpcc_bridge_dispatcher_thread, NULL,
			   "tcpcc-m9-disp");
	if (IS_ERR(task)) {
		status = PTR_ERR(task);
		tcpcc_host_runtime_event_clear_notifier(
			tcpcc_bridge_dispatcher_wake, &tcpcc_bridge_manager);
		return status;
	}

	get_task_struct(task);
	tcpcc_bridge_manager.dispatcher_task = task;
	WRITE_ONCE(tcpcc_bridge_manager.dispatcher_running, true);
	tcpcc_bridge_dispatcher_wake(NULL);
	pr_notice("tcpcc: M9.4 dynamic bridge dispatcher started\n");
	return 0;
}

static struct tcpcc_bridge_slot *tcpcc_bridge_allocate_slot(void)
{
	struct tcpcc_bridge_slot *slot;
	unsigned long flags;
	int id;

	/*
	 * Reuse the most recently released slot so stale-handle detection is
	 * exercised immediately while preserving the slot's generation.
	 */
	if (!list_empty(&tcpcc_bridge_manager.free_slots)) {
		slot = list_first_entry(&tcpcc_bridge_manager.free_slots,
					struct tcpcc_bridge_slot, free_node);
		list_del_init(&slot->free_node);
		return slot;
	}

	slot = kzalloc(sizeof(*slot), GFP_KERNEL);
	if (!slot)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&slot->free_node);
	idr_preload(GFP_KERNEL);
	spin_lock_irqsave(&tcpcc_bridge_manager.registry_lock, flags);
	id = idr_alloc(&tcpcc_bridge_manager.slots, slot, 1,
		       TCPCC_BRIDGE_SESSION_LIMIT + 1, GFP_NOWAIT);
	spin_unlock_irqrestore(&tcpcc_bridge_manager.registry_lock, flags);
	idr_preload_end();
	if (id < 0) {
		kfree(slot);
		return ERR_PTR(id);
	}
	slot->id = id;
	return slot;
}

static struct tcpcc_bridge_session *tcpcc_bridge_find_handle(int handle)
{
	struct tcpcc_bridge_slot *slot_entry;
	struct tcpcc_bridge_session *session;
	unsigned long flags;
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

	spin_lock_irqsave(&tcpcc_bridge_manager.registry_lock, flags);
	slot_entry = idr_find(&tcpcc_bridge_manager.slots, slot);
	session = slot_entry ? slot_entry->session : NULL;
	if (!session || !session->allocated || session->handle != handle ||
	    session->generation != generation)
		session = NULL;
	spin_unlock_irqrestore(&tcpcc_bridge_manager.registry_lock, flags);
	return session;
}

static struct tcpcc_bridge_session *tcpcc_bridge_allocate_session(
					struct socket *public_sock)
{
	struct tcpcc_bridge_session *session;
	struct tcpcc_bridge_slot *slot;
	unsigned long flags;
	u32 generation;

	slot = tcpcc_bridge_allocate_slot();
	if (IS_ERR(slot))
		return ERR_CAST(slot);
	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session) {
		list_add(&slot->free_node, &tcpcc_bridge_manager.free_slots);
		return ERR_PTR(-ENOMEM);
	}
	generation = tcpcc_bridge_next_generation(slot->generation);
	slot->generation = generation;

	INIT_LIST_HEAD(&session->active_node);
	INIT_LIST_HEAD(&session->ready_node);
	INIT_LIST_HEAD(&session->retired_node);
	INIT_LIST_HEAD(&session->buffer_wait_node);
	spin_lock_init(&session->lock);
	atomic_set(&session->event_refs, 0);
	init_completion(&session->finished);
	init_completion(&session->connect_ready);
	init_completion(&session->event_idle);
	session->registered = false;
	session->public_callbacks_installed = false;
	session->saved_data_ready = NULL;
	session->saved_write_space = NULL;
	session->saved_state_change = NULL;
	session->saved_error_report = NULL;

	session->slot = slot;
	session->public_sock = public_sock;
	session->host_fd = -1;
	session->generation = generation;
	session->handle = tcpcc_bridge_make_handle(slot->id - 1U, generation);
	session->token = TCPCC_HOST_EVENT_RUNTIME_TOKEN(
		TCPCC_BRIDGE_RUNTIME_SLOT_BASE + slot->id - 1U, generation);
	session->status = 0;
	session->connect_events = 0;
	session->terminal_events = 0;
	session->host_send_eagain = 0;
	session->host_partial_writes = 0;
	session->host_recv_eagain = 0;
	session->public_to_backend_bytes = 0;
	session->backend_to_public_bytes = 0;
	session->public_to_backend_offset = 0;
	session->public_to_backend_length = 0;
	session->backend_to_public_offset = 0;
	session->backend_to_public_length = 0;
	session->public_readable = false;
	session->public_writable = false;
	session->host_readable = false;
	session->host_writable = false;
	session->public_to_backend_done = false;
	session->backend_to_public_done = false;
	session->finished_notified = false;
	session->connecting = true;
	session->running = false;
	session->stopping = false;
	session->accept_events = true;
	session->allocated = true;

	spin_lock_irqsave(&tcpcc_bridge_manager.registry_lock, flags);
	slot->session = session;
	spin_unlock_irqrestore(&tcpcc_bridge_manager.registry_lock, flags);
	list_add_tail(&session->active_node, &tcpcc_bridge_manager.active);

	tcpcc_bridge_manager.active_sessions++;
	return session;
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
	struct tcpcc_bridge_slot *slot = session->slot;
	unsigned long flags;

	tcpcc_bridge_unqueue_session(session);
	spin_lock_irqsave(&tcpcc_bridge_manager.registry_lock, flags);
	if (slot->session == session)
		slot->session = NULL;
	spin_unlock_irqrestore(&tcpcc_bridge_manager.registry_lock, flags);
	list_del_init(&session->active_node);
	list_add(&slot->free_node, &tcpcc_bridge_manager.free_slots);

	spin_lock_irqsave(&session->lock, flags);
	session->public_sock = NULL;
	session->connecting = false;
	session->running = false;
	session->stopping = false;
	session->accept_events = false;
	session->allocated = false;
	spin_unlock_irqrestore(&session->lock, flags);
	tcpcc_bridge_manager.active_sessions--;
	spin_lock_irqsave(&tcpcc_bridge_manager.ready_lock, flags);
	list_add_tail(&session->retired_node, &tcpcc_bridge_manager.retired);
	spin_unlock_irqrestore(&tcpcc_bridge_manager.ready_lock, flags);
	tcpcc_bridge_dispatcher_wake(NULL);
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

	session = tcpcc_bridge_allocate_session(public_sock);
	if (IS_ERR(session)) {
		ret = PTR_ERR(session);
		goto unlock;
	}

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
	ret = tcpcc_bridge_install_public_callbacks(session);
	if (ret)
		goto fail;
	ret = tcpcc_host_event_mod_mask(
		session->host_fd, session->token,
		TCPCC_HOST_EVENT_READABLE | TCPCC_HOST_EVENT_WRITABLE, true);
	if (ret)
		goto fail;

	spin_lock_irqsave(&session->lock, flags);
	session->connecting = false;
	session->public_readable = true;
	session->public_writable = true;
	session->host_readable = true;
	session->host_writable = true;
	session->running = true;
	spin_unlock_irqrestore(&session->lock, flags);
	*handle = session->handle;
	tcpcc_bridge_queue_session(session);
	mutex_unlock(&tcpcc_bridge_control_lock);
	return 0;

fail:
	tcpcc_bridge_restore_public_callbacks(session);
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
	struct tcpcc_bridge_slot *slot = session->slot;
	struct socket *public_sock;
	unsigned long flags;
	int cleanup_status;
	int close_status;
	int status;

	cleanup_status = tcpcc_bridge_disable_events(session);
	tcpcc_bridge_restore_public_callbacks(session);
	tcpcc_bridge_unqueue_session(session);
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
	spin_lock_irqsave(&tcpcc_bridge_manager.registry_lock, flags);
	if (slot->session == session)
		slot->session = NULL;
	spin_unlock_irqrestore(&tcpcc_bridge_manager.registry_lock, flags);
	list_del_init(&session->active_node);
	list_add(&slot->free_node, &tcpcc_bridge_manager.free_slots);
	tcpcc_bridge_manager.active_sessions--;

	spin_lock_irqsave(&tcpcc_bridge_manager.ready_lock, flags);
	list_add_tail(&session->retired_node, &tcpcc_bridge_manager.retired);
	spin_unlock_irqrestore(&tcpcc_bridge_manager.ready_lock, flags);
	tcpcc_bridge_dispatcher_wake(NULL);
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

int tcpcc_bridge_try_join_result(int handle,
				 struct tcpcc_bridge_result *result)
{
	struct tcpcc_bridge_session *session;
	int ret = 0;

	mutex_lock(&tcpcc_bridge_control_lock);
	session = tcpcc_bridge_find_handle(handle);
	if (!session) {
		ret = -ENOENT;
		goto unlock;
	}
	if (!try_wait_for_completion(&session->finished)) {
		ret = -EAGAIN;
		goto unlock;
	}
	tcpcc_bridge_reap(session, result);
unlock:
	mutex_unlock(&tcpcc_bridge_control_lock);
	return ret;
}

int tcpcc_bridge_set_completion_notifier(void (*notify)(void *), void *data)
{
	int ret = 0;

	if (!notify)
		return -EINVAL;
	mutex_lock(&tcpcc_bridge_control_lock);
	tcpcc_bridge_manager_init();
	if (tcpcc_bridge_manager.active_sessions ||
	    tcpcc_bridge_manager.completion_notify) {
		ret = -EBUSY;
		goto unlock;
	}
	WRITE_ONCE(tcpcc_bridge_manager.completion_notify_data, data);
	smp_store_release(&tcpcc_bridge_manager.completion_notify, notify);
unlock:
	mutex_unlock(&tcpcc_bridge_control_lock);
	return ret;
}

void tcpcc_bridge_clear_completion_notifier(void (*notify)(void *), void *data)
{
	mutex_lock(&tcpcc_bridge_control_lock);
	if (tcpcc_bridge_manager.completion_notify == notify &&
	    tcpcc_bridge_manager.completion_notify_data == data &&
	    !tcpcc_bridge_manager.active_sessions) {
		smp_store_release(&tcpcc_bridge_manager.completion_notify, NULL);
		WRITE_ONCE(tcpcc_bridge_manager.completion_notify_data, NULL);
	}
	mutex_unlock(&tcpcc_bridge_control_lock);
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
	struct tcpcc_bridge_session *session;
	struct tcpcc_bridge_session *next;

	mutex_lock(&tcpcc_bridge_control_lock);
	if (!tcpcc_bridge_manager.initialized)
		goto unlock;

	list_for_each_entry(session, &tcpcc_bridge_manager.active, active_node)
		tcpcc_bridge_session_stop(session, -ECANCELED, true);
	list_for_each_entry_safe(session, next, &tcpcc_bridge_manager.active,
				 active_node) {
		wait_for_completion(&session->finished);
		tcpcc_bridge_reap(session, NULL);
	}

	if (tcpcc_bridge_manager.dispatcher_task) {
		WRITE_ONCE(tcpcc_bridge_manager.dispatcher_stopping, true);
		tcpcc_bridge_dispatcher_wake(NULL);
		kthread_stop_put(tcpcc_bridge_manager.dispatcher_task);
		tcpcc_bridge_manager.dispatcher_task = NULL;
		WRITE_ONCE(tcpcc_bridge_manager.dispatcher_running, false);
		tcpcc_host_runtime_event_clear_notifier(
			tcpcc_bridge_dispatcher_wake, &tcpcc_bridge_manager);
	}
unlock:
	mutex_unlock(&tcpcc_bridge_control_lock);
}

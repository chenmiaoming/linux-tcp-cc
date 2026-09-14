// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/in.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/printk.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <asm/bridge.h>
#include <asm/service.h>

struct tcpcc_service_bridge {
	struct list_head node;
	int handle;
};

struct tcpcc_service_listener {
	struct list_head node;
	struct socket *listener;
	struct tcpcc_control_service_config config;
	void (*saved_data_ready)(struct sock *sk);
	bool callback_installed;
	bool ready;
};

struct tcpcc_service_manager {
	bool allocated;
	bool draining;
	bool stopping;
	struct task_struct *task;
	struct completion work_ready;
	struct completion drained;
	struct completion stopped;
	struct tcpcc_control_service_stats stats;
	struct list_head listeners;
	struct list_head bridges;
	unsigned int listener_count;
};

static DEFINE_MUTEX(tcpcc_service_lock);
static struct tcpcc_service_manager tcpcc_service;

static void tcpcc_service_wake(void *data)
{
	struct tcpcc_service_manager *service = data;

	if (service && READ_ONCE(service->allocated))
		complete(&service->work_ready);
}

static void tcpcc_service_listener_data_ready(struct sock *sk)
{
	struct tcpcc_service_listener *entry;
	void (*saved_data_ready)(struct sock *sk) = NULL;

	read_lock_bh(&sk->sk_callback_lock);
	entry = sk->sk_user_data;
	if (entry) {
		saved_data_ready = entry->saved_data_ready;
		if (entry->listener && entry->listener->sk == sk &&
		    READ_ONCE(tcpcc_service.allocated)) {
			WRITE_ONCE(entry->ready, true);
			complete(&tcpcc_service.work_ready);
		}
	}
	if (saved_data_ready)
		saved_data_ready(sk);
	read_unlock_bh(&sk->sk_callback_lock);
}

static int tcpcc_service_install_listener_callback(
				struct tcpcc_service_listener *entry)
{
	struct sock *sk = entry->listener->sk;
	int ret = 0;

	write_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_user_data) {
		ret = -EBUSY;
		goto unlock;
	}
	entry->saved_data_ready = sk->sk_data_ready;
	sk->sk_user_data = entry;
	WRITE_ONCE(sk->sk_data_ready, tcpcc_service_listener_data_ready);
	entry->callback_installed = true;
	WRITE_ONCE(entry->ready, true);
unlock:
	write_unlock_bh(&sk->sk_callback_lock);
	return ret;
}

static void tcpcc_service_restore_listener_callback(
				struct tcpcc_service_listener *entry)
{
	struct socket *listener = entry->listener;
	struct sock *sk;

	if (!listener || !entry->callback_installed)
		return;
	sk = listener->sk;
	write_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_user_data == entry) {
		sk->sk_user_data = NULL;
		WRITE_ONCE(sk->sk_data_ready, entry->saved_data_ready);
	}
	entry->callback_installed = false;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void tcpcc_service_detach_accepted_callback(
				struct socket *public_sock,
				struct tcpcc_service_listener *entry)
{
	struct sock *sk = public_sock->sk;

	/*
	 * The accepted child can inherit the listener's sk_user_data and callback.
	 * It is no longer an admission source; restore the original data callback
	 * before the bridge installs its per-socket readiness wrapper.
	 */
	write_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_user_data == entry) {
		sk->sk_user_data = NULL;
		if (sk->sk_data_ready == tcpcc_service_listener_data_ready)
			WRITE_ONCE(sk->sk_data_ready, entry->saved_data_ready);
	}
	write_unlock_bh(&sk->sk_callback_lock);
}

static unsigned int tcpcc_service_snapshot_listeners(
				struct tcpcc_service_listener **snapshot,
				bool ready_only)
{
	struct tcpcc_service_listener *entry;
	unsigned int count = 0;

	mutex_lock(&tcpcc_service_lock);
	list_for_each_entry(entry, &tcpcc_service.listeners, node) {
		if (ready_only && !READ_ONCE(entry->ready))
			continue;
		if (count == TCPCC_SERVICE_MAX_LISTENERS)
			break;
		snapshot[count++] = entry;
	}
	mutex_unlock(&tcpcc_service_lock);
	return count;
}

static void tcpcc_service_shutdown_listeners(void)
{
	struct tcpcc_service_listener *snapshot[TCPCC_SERVICE_MAX_LISTENERS];
	unsigned int count;
	unsigned int i;

	count = tcpcc_service_snapshot_listeners(snapshot, false);
	for (i = 0; i < count; i++) {
		if (snapshot[i]->listener)
			kernel_sock_shutdown(snapshot[i]->listener, SHUT_RDWR);
	}
}

static bool tcpcc_service_reap(void)
{
	struct tcpcc_service_bridge *bridge;
	struct tcpcc_service_bridge *next;
	bool progress = false;

	list_for_each_entry_safe(bridge, next, &tcpcc_service.bridges, node) {
		struct tcpcc_bridge_result result;
		int ret;

		ret = tcpcc_bridge_try_join_result(bridge->handle, &result);
		if (ret == -EAGAIN)
			continue;

		mutex_lock(&tcpcc_service_lock);
		list_del(&bridge->node);
		if (tcpcc_service.stats.active_connections)
			tcpcc_service.stats.active_connections--;
		tcpcc_service.stats.completed_connections++;
		if (ret) {
			tcpcc_service.stats.terminal_failures++;
			tcpcc_service.stats.last_error = ret;
		} else {
			tcpcc_service.stats.public_to_backend_bytes +=
				result.public_to_backend_bytes;
			tcpcc_service.stats.backend_to_public_bytes +=
				result.backend_to_public_bytes;
			if (result.status) {
				tcpcc_service.stats.terminal_failures++;
				tcpcc_service.stats.last_error = result.status;
			}
		}
		mutex_unlock(&tcpcc_service_lock);
		kfree(bridge);
		progress = true;
	}
	return progress;
}

static void tcpcc_service_fail(int status)
{
	mutex_lock(&tcpcc_service_lock);
	if (!tcpcc_service.draining) {
		tcpcc_service.draining = true;
		tcpcc_service.stats.state = TCPCC_CONTROL_SERVICE_FAILED;
	}
	tcpcc_service.stats.last_error = status;
	mutex_unlock(&tcpcc_service_lock);
	tcpcc_service_shutdown_listeners();
}

static bool tcpcc_service_admission_available(void)
{
	bool available;

	mutex_lock(&tcpcc_service_lock);
	available = !tcpcc_service.draining && !tcpcc_service.stopping &&
		(!tcpcc_service.stats.max_connections ||
		 tcpcc_service.stats.active_connections <
			tcpcc_service.stats.max_connections);
	mutex_unlock(&tcpcc_service_lock);
	return available;
}

static int tcpcc_service_accept_one(struct tcpcc_service_listener *entry)
{
	struct tcpcc_service_bridge *bridge;
	struct socket *public_sock;
	bool cancel = false;
	int bridge_handle;
	int ret;

	if (!tcpcc_service_admission_available())
		return 0;

	/*
	 * Clear readiness before the nonblocking accept. A callback racing after
	 * this store will set it again, so an EAGAIN cannot lose a new edge.
	 */
	WRITE_ONCE(entry->ready, false);
	ret = kernel_accept(entry->listener, &public_sock, O_NONBLOCK);
	if (ret == -EAGAIN) {
		mutex_lock(&tcpcc_service_lock);
		tcpcc_service.stats.accept_eagain++;
		mutex_unlock(&tcpcc_service_lock);
		return 0;
	}
	if (ret) {
		tcpcc_service_fail(ret);
		return ret;
	}

	/* A successful accept may leave more sockets queued on this listener. */
	WRITE_ONCE(entry->ready, true);
	tcpcc_service_detach_accepted_callback(public_sock, entry);
	bridge = kzalloc(sizeof(*bridge), GFP_KERNEL);
	if (!bridge) {
		kernel_sock_shutdown(public_sock, SHUT_RDWR);
		sock_release(public_sock);
		mutex_lock(&tcpcc_service_lock);
		tcpcc_service.stats.rejected_connections++;
		tcpcc_service.stats.bridge_start_failures++;
		tcpcc_service.stats.last_error = -ENOMEM;
		mutex_unlock(&tcpcc_service_lock);
		return 1;
	}
	INIT_LIST_HEAD(&bridge->node);

	ret = tcpcc_bridge_start(public_sock, htonl(entry->config.backend_ipv4),
				 htons(entry->config.backend_port), &bridge_handle);
	if (ret) {
		kfree(bridge);
		kernel_sock_shutdown(public_sock, SHUT_RDWR);
		sock_release(public_sock);
		mutex_lock(&tcpcc_service_lock);
		tcpcc_service.stats.rejected_connections++;
		tcpcc_service.stats.bridge_start_failures++;
		tcpcc_service.stats.last_error = ret;
		mutex_unlock(&tcpcc_service_lock);
		return 1;
	}

	mutex_lock(&tcpcc_service_lock);
	bridge->handle = bridge_handle;
	list_add_tail(&bridge->node, &tcpcc_service.bridges);
	tcpcc_service.stats.accepted_connections++;
	tcpcc_service.stats.active_connections++;
	if (tcpcc_service.stats.active_connections >
	    tcpcc_service.stats.peak_connections)
		tcpcc_service.stats.peak_connections =
			tcpcc_service.stats.active_connections;
	cancel = tcpcc_service.stopping;
	mutex_unlock(&tcpcc_service_lock);
	if (cancel)
		tcpcc_bridge_cancel_session(bridge_handle);
	return 1;
}

static bool tcpcc_service_accept_ready(void)
{
	struct tcpcc_service_listener *snapshot[TCPCC_SERVICE_MAX_LISTENERS];
	unsigned int budget;
	bool progress = false;

	mutex_lock(&tcpcc_service_lock);
	budget = tcpcc_service.stats.accept_batch;
	mutex_unlock(&tcpcc_service_lock);

	while (budget && tcpcc_service_admission_available()) {
		unsigned int count;
		unsigned int i;
		bool round_progress = false;

		count = tcpcc_service_snapshot_listeners(snapshot, true);
		if (!count)
			break;
		for (i = 0; i < count && budget; i++) {
			int ret = tcpcc_service_accept_one(snapshot[i]);

			if (ret < 0)
				return progress;
			if (!ret)
				continue;
			budget--;
			progress = true;
			round_progress = true;
		}
		if (!round_progress)
			break;
	}

	if (!budget && tcpcc_service_snapshot_listeners(snapshot, true))
		complete(&tcpcc_service.work_ready);
	return progress;
}

static bool tcpcc_service_should_stop(void)
{
	bool stop;

	mutex_lock(&tcpcc_service_lock);
	if (tcpcc_service.draining &&
	    !tcpcc_service.stats.active_connections)
		complete_all(&tcpcc_service.drained);
	stop = tcpcc_service.stopping &&
	       !tcpcc_service.stats.active_connections;
	mutex_unlock(&tcpcc_service_lock);
	return stop;
}

static int tcpcc_service_thread(void *unused)
{
	for (;;) {
		wait_for_completion(&tcpcc_service.work_ready);
		tcpcc_service_reap();
		if (!READ_ONCE(tcpcc_service.draining) &&
		    !READ_ONCE(tcpcc_service.stopping))
			tcpcc_service_accept_ready();
		if (tcpcc_service_should_stop())
			break;
		if (kthread_should_stop())
			break;
	}
	complete_all(&tcpcc_service.stopped);
	return 0;
}

static void tcpcc_service_reset_start(
			const struct tcpcc_control_service_config *config)
{
	memset(&tcpcc_service.stats, 0, sizeof(tcpcc_service.stats));
	INIT_LIST_HEAD(&tcpcc_service.listeners);
	INIT_LIST_HEAD(&tcpcc_service.bridges);
	init_completion(&tcpcc_service.work_ready);
	init_completion(&tcpcc_service.drained);
	init_completion(&tcpcc_service.stopped);
	tcpcc_service.stats.max_connections = config->max_connections;
	tcpcc_service.stats.accept_batch = config->accept_batch;
	tcpcc_service.stats.state = TCPCC_CONTROL_SERVICE_RUNNING;
	tcpcc_service.task = NULL;
	tcpcc_service.listener_count = 0;
	tcpcc_service.draining = false;
	tcpcc_service.stopping = false;
	tcpcc_service.allocated = true;
}

static bool tcpcc_service_policy_matches(
			const struct tcpcc_control_service_config *config)
{
	return tcpcc_service.stats.max_connections == config->max_connections &&
	       tcpcc_service.stats.accept_batch == config->accept_batch;
}

static void tcpcc_service_unlink_listener(
				struct tcpcc_service_listener *entry)
{
	mutex_lock(&tcpcc_service_lock);
	if (!list_empty(&entry->node)) {
		list_del_init(&entry->node);
		if (tcpcc_service.listener_count)
			tcpcc_service.listener_count--;
	}
	mutex_unlock(&tcpcc_service_lock);
	tcpcc_service_restore_listener_callback(entry);
}

int tcpcc_service_start(struct socket *listener,
			const struct tcpcc_control_service_config *config,
			int *handle)
{
	struct tcpcc_service_listener *entry;
	struct task_struct *task;
	bool first;
	int ret;

	if (!listener || !listener->sk || !config || !handle ||
	    config->backend_ipv4 != INADDR_LOOPBACK || !config->backend_port ||
	    config->reserved ||
	    config->max_connections > TCPCC_BRIDGE_SESSION_LIMIT ||
	    !config->accept_batch ||
	    config->accept_batch > TCPCC_SERVICE_MAX_ACCEPT_BATCH)
		return -EINVAL;
	if (listener->sk->sk_state != TCP_LISTEN)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->node);
	entry->listener = listener;
	entry->config = *config;

	mutex_lock(&tcpcc_service_lock);
	first = !tcpcc_service.allocated;
	if (first) {
		tcpcc_service_reset_start(config);
	} else if (tcpcc_service.draining || tcpcc_service.stopping) {
		ret = -EBUSY;
		goto unlock_free;
	} else if (!tcpcc_service_policy_matches(config)) {
		ret = -EINVAL;
		goto unlock_free;
	} else if (tcpcc_service.listener_count >= TCPCC_SERVICE_MAX_LISTENERS) {
		ret = -ENOSPC;
		goto unlock_free;
	}
	mutex_unlock(&tcpcc_service_lock);

	if (first) {
		ret = tcpcc_bridge_set_completion_notifier(tcpcc_service_wake,
						   &tcpcc_service);
		if (ret)
			goto reset_first;
	}
	ret = tcpcc_service_install_listener_callback(entry);
	if (ret)
		goto clear_first;

	mutex_lock(&tcpcc_service_lock);
	list_add_tail(&entry->node, &tcpcc_service.listeners);
	tcpcc_service.listener_count++;
	mutex_unlock(&tcpcc_service_lock);

	if (first) {
		task = kthread_run(tcpcc_service_thread, NULL, "tcpcc-m9-service");
		if (IS_ERR(task)) {
			ret = PTR_ERR(task);
			goto unlink_first;
		}
		get_task_struct(task);
		mutex_lock(&tcpcc_service_lock);
		tcpcc_service.task = task;
		mutex_unlock(&tcpcc_service_lock);
	}

	*handle = TCPCC_SERVICE_HANDLE;
	complete(&tcpcc_service.work_ready);
	if (first) {
		if (config->max_connections)
			pr_notice("tcpcc: hosted service %d started (max %u, accept batch %u)\n",
				  *handle, config->max_connections,
				  config->accept_batch);
		else
			pr_notice("tcpcc: hosted service %d started (max unlimited, accept batch %u)\n",
				  *handle, config->accept_batch);
	} else {
		pr_notice("tcpcc: hosted service %d added listener %u (backend 127.0.0.1:%u)\n",
			  *handle, tcpcc_service.listener_count,
			  config->backend_port);
	}
	return 0;

unlink_first:
	tcpcc_service_unlink_listener(entry);
clear_first:
	if (first)
		tcpcc_bridge_clear_completion_notifier(tcpcc_service_wake,
						       &tcpcc_service);
reset_first:
	if (first) {
		mutex_lock(&tcpcc_service_lock);
		tcpcc_service.allocated = false;
		tcpcc_service.listener_count = 0;
		mutex_unlock(&tcpcc_service_lock);
	}
	if (entry->callback_installed)
		tcpcc_service_restore_listener_callback(entry);
	kfree(entry);
	return ret;

unlock_free:
	mutex_unlock(&tcpcc_service_lock);
	kfree(entry);
	return ret;
}

int tcpcc_service_get_stats(int handle,
			    struct tcpcc_control_service_stats *stats)
{
	if (handle != TCPCC_SERVICE_HANDLE || !stats)
		return -EINVAL;
	mutex_lock(&tcpcc_service_lock);
	if (!tcpcc_service.allocated) {
		mutex_unlock(&tcpcc_service_lock);
		return -ENOENT;
	}
	*stats = tcpcc_service.stats;
	mutex_unlock(&tcpcc_service_lock);
	return 0;
}

int tcpcc_service_drain(int handle, unsigned long timeout,
			struct tcpcc_control_service_stats *stats)
{
	if (handle != TCPCC_SERVICE_HANDLE || !timeout)
		return -EINVAL;
	mutex_lock(&tcpcc_service_lock);
	if (!tcpcc_service.allocated) {
		mutex_unlock(&tcpcc_service_lock);
		return -ENOENT;
	}
	tcpcc_service.draining = true;
	if (tcpcc_service.stats.state == TCPCC_CONTROL_SERVICE_RUNNING)
		tcpcc_service.stats.state = TCPCC_CONTROL_SERVICE_DRAINING;
	mutex_unlock(&tcpcc_service_lock);

	tcpcc_service_shutdown_listeners();
	complete(&tcpcc_service.work_ready);
	if (!wait_for_completion_timeout(&tcpcc_service.drained, timeout))
		return -ETIMEDOUT;
	return stats ? tcpcc_service_get_stats(handle, stats) : 0;
}

static void tcpcc_service_cancel_bridges(void)
{
	struct tcpcc_service_bridge *bridge;

	mutex_lock(&tcpcc_service_lock);
	list_for_each_entry(bridge, &tcpcc_service.bridges, node)
		tcpcc_bridge_cancel_session(bridge->handle);
	mutex_unlock(&tcpcc_service_lock);
}

static void tcpcc_service_release_listeners(void)
{
	struct tcpcc_service_listener *entry;
	struct tcpcc_service_listener *next;
	LIST_HEAD(release);

	mutex_lock(&tcpcc_service_lock);
	list_splice_init(&tcpcc_service.listeners, &release);
	tcpcc_service.listener_count = 0;
	mutex_unlock(&tcpcc_service_lock);

	list_for_each_entry_safe(entry, next, &release, node) {
		list_del_init(&entry->node);
		tcpcc_service_restore_listener_callback(entry);
		if (entry->listener) {
			kernel_sock_shutdown(entry->listener, SHUT_RDWR);
			sock_release(entry->listener);
		}
		kfree(entry);
	}
}

int tcpcc_service_stop(int handle, unsigned long timeout,
		       struct tcpcc_control_service_stats *stats)
{
	struct task_struct *task;
	unsigned int listeners;

	if (handle != TCPCC_SERVICE_HANDLE || !timeout)
		return -EINVAL;
	mutex_lock(&tcpcc_service_lock);
	if (!tcpcc_service.allocated) {
		mutex_unlock(&tcpcc_service_lock);
		return -ENOENT;
	}
	tcpcc_service.draining = true;
	tcpcc_service.stopping = true;
	tcpcc_service.stats.state = TCPCC_CONTROL_SERVICE_STOPPING;
	task = tcpcc_service.task;
	listeners = tcpcc_service.listener_count;
	mutex_unlock(&tcpcc_service_lock);

	tcpcc_service_shutdown_listeners();
	tcpcc_service_cancel_bridges();
	complete(&tcpcc_service.work_ready);
	if (!wait_for_completion_timeout(&tcpcc_service.stopped, timeout))
		return -ETIMEDOUT;
	if (task)
		kthread_stop_put(task);

	tcpcc_bridge_clear_completion_notifier(tcpcc_service_wake,
					       &tcpcc_service);
	tcpcc_service_release_listeners();

	mutex_lock(&tcpcc_service_lock);
	tcpcc_service.task = NULL;
	tcpcc_service.stats.state = TCPCC_CONTROL_SERVICE_STOPPED;
	if (stats)
		*stats = tcpcc_service.stats;
	tcpcc_service.allocated = false;
	mutex_unlock(&tcpcc_service_lock);
	pr_notice("tcpcc: hosted service %d stopped (%u listeners, %llu accepted, %llu completed)\n",
		  handle, listeners,
		  (unsigned long long)tcpcc_service.stats.accepted_connections,
		  (unsigned long long)tcpcc_service.stats.completed_connections);
	return 0;
}

bool tcpcc_service_active(void)
{
	return READ_ONCE(tcpcc_service.allocated);
}

void tcpcc_service_cancel(void)
{
	if (tcpcc_service_active())
		(void)tcpcc_service_stop(TCPCC_SERVICE_HANDLE,
					 MAX_SCHEDULE_TIMEOUT, NULL);
}

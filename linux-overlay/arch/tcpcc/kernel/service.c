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

struct tcpcc_service_manager {
	bool allocated;
	bool draining;
	bool stopping;
	bool listener_callback_installed;
	struct socket *listener;
	void (*saved_data_ready)(struct sock *sk);
	struct task_struct *task;
	struct completion work_ready;
	struct completion drained;
	struct completion stopped;
	struct tcpcc_control_service_config config;
	struct tcpcc_control_service_stats stats;
	struct list_head bridges;
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
	void (*saved_data_ready)(struct sock *sk);

	read_lock_bh(&sk->sk_callback_lock);
	saved_data_ready = tcpcc_service.saved_data_ready;
	if (sk->sk_user_data == &tcpcc_service &&
	    READ_ONCE(tcpcc_service.allocated))
		complete(&tcpcc_service.work_ready);
	if (saved_data_ready)
		saved_data_ready(sk);
	read_unlock_bh(&sk->sk_callback_lock);
}

static int tcpcc_service_install_listener_callback(struct socket *listener)
{
	struct sock *sk = listener->sk;
	int ret = 0;

	write_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_user_data) {
		ret = -EBUSY;
		goto unlock;
	}
	tcpcc_service.saved_data_ready = sk->sk_data_ready;
	sk->sk_user_data = &tcpcc_service;
	WRITE_ONCE(sk->sk_data_ready, tcpcc_service_listener_data_ready);
	tcpcc_service.listener_callback_installed = true;
unlock:
	write_unlock_bh(&sk->sk_callback_lock);
	return ret;
}

static void tcpcc_service_restore_listener_callback(void)
{
	struct socket *listener = tcpcc_service.listener;
	struct sock *sk;

	if (!listener || !tcpcc_service.listener_callback_installed)
		return;
	sk = listener->sk;
	write_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_user_data == &tcpcc_service) {
		sk->sk_user_data = NULL;
		WRITE_ONCE(sk->sk_data_ready,
			   tcpcc_service.saved_data_ready);
	}
	tcpcc_service.listener_callback_installed = false;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void tcpcc_service_detach_accepted_callback(struct socket *public_sock)
{
	struct sock *sk = public_sock->sk;

	/*
	 * The accepted child can inherit the listener's sk_user_data and callback.
	 * It is no longer an admission source; restore the original data callback
	 * before the bridge installs its per-socket readiness wrapper.
	 */
	write_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_user_data == &tcpcc_service) {
		sk->sk_user_data = NULL;
		if (sk->sk_data_ready == tcpcc_service_listener_data_ready)
			WRITE_ONCE(sk->sk_data_ready,
				   tcpcc_service.saved_data_ready);
	}
	write_unlock_bh(&sk->sk_callback_lock);
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
	struct socket *listener;

	mutex_lock(&tcpcc_service_lock);
	if (!tcpcc_service.draining) {
		tcpcc_service.draining = true;
		tcpcc_service.stats.state = TCPCC_CONTROL_SERVICE_FAILED;
	}
	tcpcc_service.stats.last_error = status;
	listener = tcpcc_service.listener;
	mutex_unlock(&tcpcc_service_lock);
	if (listener)
		kernel_sock_shutdown(listener, SHUT_RDWR);
}

static bool tcpcc_service_accept_batch(void)
{
	unsigned int accepted = 0;
	bool progress = false;

	while (accepted < tcpcc_service.config.accept_batch) {
		struct tcpcc_service_bridge *bridge;
		struct socket *public_sock;
		bool cancel = false;
		int bridge_handle;
		int ret;

		mutex_lock(&tcpcc_service_lock);
		if (tcpcc_service.draining || tcpcc_service.stopping ||
		    (tcpcc_service.config.max_connections &&
		     tcpcc_service.stats.active_connections >=
			tcpcc_service.config.max_connections)) {
			mutex_unlock(&tcpcc_service_lock);
			break;
		}
		mutex_unlock(&tcpcc_service_lock);

		ret = kernel_accept(tcpcc_service.listener, &public_sock,
				    O_NONBLOCK);
		if (ret == -EAGAIN) {
			mutex_lock(&tcpcc_service_lock);
			tcpcc_service.stats.accept_eagain++;
			mutex_unlock(&tcpcc_service_lock);
			break;
		}
		if (ret) {
			tcpcc_service_fail(ret);
			break;
		}
		accepted++;
		progress = true;
		tcpcc_service_detach_accepted_callback(public_sock);
		bridge = kzalloc(sizeof(*bridge), GFP_KERNEL);
		if (!bridge) {
			kernel_sock_shutdown(public_sock, SHUT_RDWR);
			sock_release(public_sock);
			mutex_lock(&tcpcc_service_lock);
			tcpcc_service.stats.rejected_connections++;
			tcpcc_service.stats.bridge_start_failures++;
			tcpcc_service.stats.last_error = -ENOMEM;
			mutex_unlock(&tcpcc_service_lock);
			continue;
		}
		INIT_LIST_HEAD(&bridge->node);

		ret = tcpcc_bridge_start(
			public_sock, htonl(tcpcc_service.config.backend_ipv4),
			htons(tcpcc_service.config.backend_port), &bridge_handle);
		if (ret) {
			kfree(bridge);
			kernel_sock_shutdown(public_sock, SHUT_RDWR);
			sock_release(public_sock);
			mutex_lock(&tcpcc_service_lock);
			tcpcc_service.stats.rejected_connections++;
			tcpcc_service.stats.bridge_start_failures++;
			tcpcc_service.stats.last_error = ret;
			mutex_unlock(&tcpcc_service_lock);
			continue;
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
	}

	if (accepted == tcpcc_service.config.accept_batch)
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
			tcpcc_service_accept_batch();
		if (tcpcc_service_should_stop())
			break;
		if (kthread_should_stop())
			break;
	}
	complete_all(&tcpcc_service.stopped);
	return 0;
}

static void tcpcc_service_reset_start(
			const struct tcpcc_control_service_config *config,
			struct socket *listener)
{
	memset(&tcpcc_service.stats, 0, sizeof(tcpcc_service.stats));
	INIT_LIST_HEAD(&tcpcc_service.bridges);
	init_completion(&tcpcc_service.work_ready);
	init_completion(&tcpcc_service.drained);
	init_completion(&tcpcc_service.stopped);
	tcpcc_service.config = *config;
	tcpcc_service.stats.max_connections = config->max_connections;
	tcpcc_service.stats.accept_batch = config->accept_batch;
	tcpcc_service.stats.state = TCPCC_CONTROL_SERVICE_RUNNING;
	tcpcc_service.listener = listener;
	tcpcc_service.saved_data_ready = NULL;
	tcpcc_service.task = NULL;
	tcpcc_service.listener_callback_installed = false;
	tcpcc_service.draining = false;
	tcpcc_service.stopping = false;
	tcpcc_service.allocated = true;
}

int tcpcc_service_start(struct socket *listener,
			const struct tcpcc_control_service_config *config,
			int *handle)
{
	struct task_struct *task;
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

	mutex_lock(&tcpcc_service_lock);
	if (tcpcc_service.allocated) {
		mutex_unlock(&tcpcc_service_lock);
		return -EBUSY;
	}
	tcpcc_service_reset_start(config, listener);
	mutex_unlock(&tcpcc_service_lock);

	ret = tcpcc_bridge_set_completion_notifier(tcpcc_service_wake,
					   &tcpcc_service);
	if (ret)
		goto reset;
	ret = tcpcc_service_install_listener_callback(listener);
	if (ret)
		goto clear_notifier;

	task = kthread_run(tcpcc_service_thread, NULL, "tcpcc-m9-service");
	if (IS_ERR(task)) {
		ret = PTR_ERR(task);
		goto restore_callback;
	}
	get_task_struct(task);
	mutex_lock(&tcpcc_service_lock);
	tcpcc_service.task = task;
	mutex_unlock(&tcpcc_service_lock);
	*handle = TCPCC_SERVICE_HANDLE;
	complete(&tcpcc_service.work_ready);
	if (config->max_connections)
		pr_notice("tcpcc: M9.2 hosted service %d started (max %u, accept batch %u)\n",
			  *handle, config->max_connections,
			  config->accept_batch);
	else
		pr_notice("tcpcc: M9.2 hosted service %d started (max unlimited, accept batch %u)\n",
			  *handle, config->accept_batch);
	return 0;

restore_callback:
	tcpcc_service_restore_listener_callback();
clear_notifier:
	tcpcc_bridge_clear_completion_notifier(tcpcc_service_wake,
					       &tcpcc_service);
reset:
	mutex_lock(&tcpcc_service_lock);
	tcpcc_service.listener = NULL;
	tcpcc_service.allocated = false;
	mutex_unlock(&tcpcc_service_lock);
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
	struct socket *listener;

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
	listener = tcpcc_service.listener;
	mutex_unlock(&tcpcc_service_lock);

	if (listener)
		kernel_sock_shutdown(listener, SHUT_RDWR);
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

int tcpcc_service_stop(int handle, unsigned long timeout,
		       struct tcpcc_control_service_stats *stats)
{
	struct task_struct *task;
	struct socket *listener;

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
	listener = tcpcc_service.listener;
	task = tcpcc_service.task;
	mutex_unlock(&tcpcc_service_lock);

	if (listener)
		kernel_sock_shutdown(listener, SHUT_RDWR);
	tcpcc_service_cancel_bridges();
	complete(&tcpcc_service.work_ready);
	if (!wait_for_completion_timeout(&tcpcc_service.stopped, timeout))
		return -ETIMEDOUT;
	if (task)
		kthread_stop_put(task);

	tcpcc_bridge_clear_completion_notifier(tcpcc_service_wake,
					       &tcpcc_service);
	tcpcc_service_restore_listener_callback();
	if (listener) {
		kernel_sock_shutdown(listener, SHUT_RDWR);
		sock_release(listener);
	}

	mutex_lock(&tcpcc_service_lock);
	tcpcc_service.task = NULL;
	tcpcc_service.listener = NULL;
	tcpcc_service.stats.state = TCPCC_CONTROL_SERVICE_STOPPED;
	if (stats)
		*stats = tcpcc_service.stats;
	tcpcc_service.allocated = false;
	mutex_unlock(&tcpcc_service_lock);
	pr_notice("tcpcc: M9.2 hosted service %d stopped (%llu accepted, %llu completed)\n",
		  handle,
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

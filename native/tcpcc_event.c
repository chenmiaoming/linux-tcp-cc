// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_event.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

static int tcpcc_event_fail(struct tcpcc_control_error *error, int code,
			    const char *format, ...)
{
	va_list arguments;

	if (error) {
		error->code = code;
		va_start(arguments, format);
		vsnprintf(error->message, sizeof(error->message), format, arguments);
		va_end(arguments);
	}
	return -1;
}

static int tcpcc_event_control(struct tcpcc_event_loop *loop, int operation,
			       int fd, uint32_t events, uint64_t token,
			       struct tcpcc_control_error *error)
{
	struct epoll_event event = {
		.events = events | EPOLLET,
		.data.u64 = token,
	};

	if (!loop || loop->epoll_fd < 0 || fd < 0 || !events || !token)
		return tcpcc_event_fail(error, EINVAL,
			"event-loop registration arguments are invalid");
	if (epoll_ctl(loop->epoll_fd, operation, fd, &event) != 0)
		return tcpcc_event_fail(error, errno,
			"epoll_ctl for fd %d failed: %s", fd, strerror(errno));
	return 0;
}

int tcpcc_event_loop_init(struct tcpcc_event_loop *loop,
			  struct tcpcc_control_error *error)
{
	int fd;

	if (!loop)
		return tcpcc_event_fail(error, EINVAL,
			"event-loop pointer is null");
	loop->epoll_fd = -1;
	fd = epoll_create1(EPOLL_CLOEXEC);
	if (fd < 0)
		return tcpcc_event_fail(error, errno,
			"epoll_create1 failed: %s", strerror(errno));
	loop->epoll_fd = fd;
	if (error) {
		error->code = 0;
		error->message[0] = '\0';
	}
	return 0;
}

int tcpcc_event_loop_add(struct tcpcc_event_loop *loop, int fd,
			 uint32_t events, uint64_t token,
			 struct tcpcc_control_error *error)
{
	return tcpcc_event_control(loop, EPOLL_CTL_ADD, fd, events, token, error);
}

int tcpcc_event_loop_modify(struct tcpcc_event_loop *loop, int fd,
			    uint32_t events, uint64_t token,
			    struct tcpcc_control_error *error)
{
	return tcpcc_event_control(loop, EPOLL_CTL_MOD, fd, events, token, error);
}

int tcpcc_event_loop_remove(struct tcpcc_event_loop *loop, int fd,
			    struct tcpcc_control_error *error)
{
	if (!loop || loop->epoll_fd < 0 || fd < 0)
		return tcpcc_event_fail(error, EINVAL,
			"event-loop removal arguments are invalid");
	if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_DEL, fd, NULL) != 0)
		return tcpcc_event_fail(error, errno,
			"removing fd %d from epoll failed: %s", fd,
			strerror(errno));
	return 0;
}

int tcpcc_event_loop_wait(struct tcpcc_event_loop *loop,
			  struct tcpcc_event *events, size_t capacity,
			  int timeout_ms, struct tcpcc_control_error *error)
{
	struct epoll_event native_events[64];
	int result;
	int index;

	if (!loop || loop->epoll_fd < 0 || !events || !capacity ||
	    capacity > sizeof(native_events) / sizeof(native_events[0]) ||
	    timeout_ms < -1)
		return tcpcc_event_fail(error, EINVAL,
			"event-loop wait arguments are invalid");
	do {
		result = epoll_wait(loop->epoll_fd, native_events, (int)capacity,
				    timeout_ms);
	} while (result < 0 && errno == EINTR);
	if (result < 0)
		return tcpcc_event_fail(error, errno,
			"epoll_wait failed: %s", strerror(errno));
	for (index = 0; index < result; index++) {
		events[index].token = native_events[index].data.u64;
		events[index].events = native_events[index].events;
	}
	return result;
}

void tcpcc_event_loop_close(struct tcpcc_event_loop *loop)
{
	if (!loop)
		return;
	if (loop->epoll_fd >= 0)
		close(loop->epoll_fd);
	loop->epoll_fd = -1;
}

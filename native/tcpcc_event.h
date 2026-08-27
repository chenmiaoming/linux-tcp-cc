/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TCPCC_NATIVE_EVENT_H
#define TCPCC_NATIVE_EVENT_H

#include <stddef.h>
#include <stdint.h>

#include "tcpcc_control.h"

struct tcpcc_event_loop {
	int epoll_fd;
};

struct tcpcc_event {
	uint64_t token;
	uint32_t events;
};

int tcpcc_event_loop_init(struct tcpcc_event_loop *loop,
			  struct tcpcc_control_error *error);

int tcpcc_event_loop_add(struct tcpcc_event_loop *loop, int fd,
			 uint32_t events, uint64_t token,
			 struct tcpcc_control_error *error);

int tcpcc_event_loop_modify(struct tcpcc_event_loop *loop, int fd,
			    uint32_t events, uint64_t token,
			    struct tcpcc_control_error *error);

int tcpcc_event_loop_remove(struct tcpcc_event_loop *loop, int fd,
			    struct tcpcc_control_error *error);

int tcpcc_event_loop_wait(struct tcpcc_event_loop *loop,
			  struct tcpcc_event *events, size_t capacity,
			  int timeout_ms, struct tcpcc_control_error *error);

void tcpcc_event_loop_close(struct tcpcc_event_loop *loop);

#endif /* TCPCC_NATIVE_EVENT_H */

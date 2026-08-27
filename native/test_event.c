// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_event.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define TEST_WAKE_TOKEN  1U
#define TEST_TIMER_TOKEN 2U

static void fail(const char *message)
{
	fprintf(stderr, "native event-loop test: %s\n", message);
	exit(1);
}

int main(void)
{
	struct tcpcc_event_loop loop;
	struct tcpcc_control_error error;
	struct tcpcc_event events[4];
	struct itimerspec timer = {
		.it_value.tv_nsec = 1,
	};
	uint64_t value = 1;
	unsigned int observed = 0;
	int wake_fd;
	int timer_fd;
	int attempts;

	wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (wake_fd < 0 || timer_fd < 0)
		fail("event source creation failed");
	if (tcpcc_event_loop_init(&loop, &error) != 0)
		fail(error.message);
	if (tcpcc_event_loop_add(&loop, wake_fd, EPOLLIN, TEST_WAKE_TOKEN,
				 &error) != 0 ||
	    tcpcc_event_loop_add(&loop, timer_fd, EPOLLIN, TEST_TIMER_TOKEN,
				 &error) != 0)
		fail(error.message);
	if (write(wake_fd, &value, sizeof(value)) != (ssize_t)sizeof(value))
		fail("eventfd write failed");
	if (timerfd_settime(timer_fd, 0, &timer, NULL) != 0)
		fail("timerfd arming failed");

	for (attempts = 0; attempts < 2 && observed != 3U; attempts++) {
		int ready = tcpcc_event_loop_wait(&loop, events, 4, 2000, &error);
		int index;

		if (ready <= 0)
			fail(ready ? error.message : "event-loop wait timed out");
		for (index = 0; index < ready; index++) {
			if (!(events[index].events & EPOLLIN))
				fail("event source was not readable");
			if (events[index].token == TEST_WAKE_TOKEN) {
				if (read(wake_fd, &value, sizeof(value)) !=
				    (ssize_t)sizeof(value))
					fail("eventfd drain failed");
				observed |= 1U;
			} else if (events[index].token == TEST_TIMER_TOKEN) {
				if (read(timer_fd, &value, sizeof(value)) !=
				    (ssize_t)sizeof(value))
					fail("timerfd drain failed");
				observed |= 2U;
			} else {
				fail("unknown event token");
			}
		}
	}
	if (observed != 3U)
		fail("event loop did not deliver every ready source");

	if (tcpcc_event_loop_remove(&loop, wake_fd, &error) != 0 ||
	    tcpcc_event_loop_remove(&loop, timer_fd, &error) != 0)
		fail(error.message);
	tcpcc_event_loop_close(&loop);
	close(wake_fd);
	close(timer_fd);
	puts("native single-thread event-loop test passed");
	return 0;
}

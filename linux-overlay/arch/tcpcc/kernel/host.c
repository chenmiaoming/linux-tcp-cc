// SPDX-License-Identifier: GPL-2.0-only
#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/host.h>

#if !defined(__x86_64__)
#error "tcpcc host ABI currently requires an x86-64 Linux host"
#endif

/* Linux x86-64 host syscall ABI. Keep this private to arch/tcpcc. */
#define TCPCC_HOST_NR_READ            0
#define TCPCC_HOST_NR_WRITE           1
#define TCPCC_HOST_NR_CLOSE           3
#define TCPCC_HOST_NR_MMAP            9
#define TCPCC_HOST_NR_SOCKET          41
#define TCPCC_HOST_NR_CONNECT         42
#define TCPCC_HOST_NR_SENDTO          44
#define TCPCC_HOST_NR_RECVFROM        45
#define TCPCC_HOST_NR_SHUTDOWN        48
#define TCPCC_HOST_NR_SOCKETPAIR      53
#define TCPCC_HOST_NR_GETSOCKOPT      55
#define TCPCC_HOST_NR_FCNTL           72
#define TCPCC_HOST_NR_EPOLL_WAIT      232
#define TCPCC_HOST_NR_EPOLL_CTL       233
#define TCPCC_HOST_NR_CLOCK_GETTIME   228
#define TCPCC_HOST_NR_EXIT_GROUP      231
#define TCPCC_HOST_NR_TIMERFD_CREATE  283
#define TCPCC_HOST_NR_TIMERFD_SETTIME 286
#define TCPCC_HOST_NR_EPOLL_CREATE1   291
#define TCPCC_HOST_STDERR_FILENO      2

#define TCPCC_HOST_CLOCK_MONOTONIC 1
#define TCPCC_HOST_EINTR            4
#define TCPCC_HOST_EIO              5
#define TCPCC_HOST_EINVAL          22
#define TCPCC_HOST_ETIMEDOUT      110

#define TCPCC_HOST_AF_UNIX     1
#define TCPCC_HOST_AF_INET     2
#define TCPCC_HOST_SOCK_STREAM 1
#define TCPCC_HOST_IPPROTO_TCP 6

#define TCPCC_HOST_SOL_SOCKET   1
#define TCPCC_HOST_SO_ERROR     4
#define TCPCC_HOST_MSG_NOSIGNAL 0x4000

#define TCPCC_HOST_F_GETFL    3
#define TCPCC_HOST_F_SETFL    4
#define TCPCC_HOST_O_NONBLOCK 0x800

#define TCPCC_HOST_PROT_READ      0x1
#define TCPCC_HOST_PROT_WRITE     0x2
#define TCPCC_HOST_MAP_PRIVATE    0x02
#define TCPCC_HOST_MAP_ANONYMOUS  0x20

#define TCPCC_HOST_EPOLLIN        0x001
#define TCPCC_HOST_EPOLLOUT       0x004
#define TCPCC_HOST_EPOLLERR       0x008
#define TCPCC_HOST_EPOLLHUP       0x010
#define TCPCC_HOST_EPOLLRDHUP     0x2000
#define TCPCC_HOST_EPOLLET        0x80000000U
#define TCPCC_HOST_EPOLL_CTL_ADD 1
#define TCPCC_HOST_EPOLL_CTL_DEL 2
#define TCPCC_HOST_EPOLL_CTL_MOD 3

#define TCPCC_HOST_NSEC_PER_SEC 1000000000ULL
#define TCPCC_HOST_EVENT_TEST_TOKEN 0x4d382e3245564e54ULL

struct tcpcc_host_timespec {
	long tv_sec;
	long tv_nsec;
};

struct tcpcc_host_itimerspec {
	struct tcpcc_host_timespec it_interval;
	struct tcpcc_host_timespec it_value;
};

struct tcpcc_host_sockaddr_in {
	u16 family;
	__be16 port;
	__be32 address;
	u8 zero[8];
};

/* x86-64 UAPI struct epoll_event is packed to 12 bytes. */
struct tcpcc_host_epoll_event {
	u32 events;
	u64 data;
} __packed;

static int tcpcc_host_epoll_fd = -1;

static __always_inline long tcpcc_host_syscall1(long nr, long arg0)
{
	long ret;

	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0)
		     : "rcx", "r11", "memory");
	return ret;
}

static __always_inline long tcpcc_host_syscall2(long nr, long arg0,
					 long arg1)
{
	long ret;

	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1)
		     : "rcx", "r11", "memory");
	return ret;
}

static __always_inline long tcpcc_host_syscall3(long nr, long arg0,
					 long arg1, long arg2)
{
	long ret;

	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "rcx", "r11", "memory");
	return ret;
}

static __always_inline long tcpcc_host_syscall4(long nr, long arg0,
					 long arg1, long arg2, long arg3)
{
	register long r10 asm("r10") = arg3;
	long ret;

	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2),
		       "r" (r10)
		     : "rcx", "r11", "memory");
	return ret;
}

static __always_inline long tcpcc_host_syscall5(long nr, long arg0,
					 long arg1, long arg2,
					 long arg3, long arg4)
{
	register long r10 asm("r10") = arg3;
	register long r8 asm("r8") = arg4;
	long ret;

	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2),
		       "r" (r10), "r" (r8)
		     : "rcx", "r11", "memory");
	return ret;
}

static __always_inline long tcpcc_host_syscall6(long nr, long arg0,
					 long arg1, long arg2,
					 long arg3, long arg4,
					 long arg5)
{
	register long r10 asm("r10") = arg3;
	register long r8 asm("r8") = arg4;
	register long r9 asm("r9") = arg5;
	long ret;

	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2),
		       "r" (r10), "r" (r8), "r" (r9)
		     : "rcx", "r11", "memory");
	return ret;
}

ssize_t tcpcc_host_read_fd(int fd, void *buf, size_t len)
{
	long ret;

	do {
		ret = tcpcc_host_syscall3(TCPCC_HOST_NR_READ, fd,
					 (long)buf, (long)len);
	} while (ret == -TCPCC_HOST_EINTR);

	return (ssize_t)ret;
}

ssize_t tcpcc_host_write_fd(int fd, const void *buf, size_t len)
{
	long ret;

	do {
		ret = tcpcc_host_syscall3(TCPCC_HOST_NR_WRITE, fd,
					 (long)buf, (long)len);
	} while (ret == -TCPCC_HOST_EINTR);

	return (ssize_t)ret;
}

void tcpcc_host_write(const char *buf, size_t len)
{
	while (len) {
		ssize_t ret = tcpcc_host_write_fd(TCPCC_HOST_STDERR_FILENO,
						      buf, len);

		/* A failed host write must never recurse back through printk. */
		if (ret <= 0)
			return;

		buf += ret;
		len -= ret;
	}
}

int tcpcc_host_close(int fd)
{
	long ret = tcpcc_host_syscall1(TCPCC_HOST_NR_CLOSE, fd);

	return ret < 0 ? (int)ret : 0;
}

int tcpcc_host_set_nonblock(int fd)
{
	long flags;
	long ret;

	flags = tcpcc_host_syscall2(TCPCC_HOST_NR_FCNTL, fd,
				    TCPCC_HOST_F_GETFL);
	if (flags < 0)
		return (int)flags;

	ret = tcpcc_host_syscall3(TCPCC_HOST_NR_FCNTL, fd,
				  TCPCC_HOST_F_SETFL,
				  flags | TCPCC_HOST_O_NONBLOCK);
	return ret < 0 ? (int)ret : 0;
}

int tcpcc_host_tcp_socket(void)
{
	long ret;
	int fd;

	ret = tcpcc_host_syscall3(TCPCC_HOST_NR_SOCKET, TCPCC_HOST_AF_INET,
				 TCPCC_HOST_SOCK_STREAM,
				 TCPCC_HOST_IPPROTO_TCP);
	if (ret < 0)
		return (int)ret;

	fd = (int)ret;
	ret = tcpcc_host_set_nonblock(fd);
	if (ret) {
		tcpcc_host_close(fd);
		return (int)ret;
	}

	return fd;
}

int tcpcc_host_tcp_connect(int fd, __be32 address, __be16 port)
{
	struct tcpcc_host_sockaddr_in addr = {
		.family = TCPCC_HOST_AF_INET,
		.port = port,
		.address = address,
	};
	long ret;

	ret = tcpcc_host_syscall3(TCPCC_HOST_NR_CONNECT, fd, (long)&addr,
				 sizeof(addr));
	return ret < 0 ? (int)ret : 0;
}

int tcpcc_host_socket_error(int fd)
{
	u32 length = sizeof(int);
	int error = 0;
	long ret;

	ret = tcpcc_host_syscall5(TCPCC_HOST_NR_GETSOCKOPT, fd,
				 TCPCC_HOST_SOL_SOCKET, TCPCC_HOST_SO_ERROR,
				 (long)&error, (long)&length);
	if (ret < 0)
		return (int)ret;
	if (length != sizeof(error))
		return -TCPCC_HOST_EIO;
	return error ? -error : 0;
}

ssize_t tcpcc_host_send_fd(int fd, const void *buf, size_t len)
{
	long ret;

	do {
		ret = tcpcc_host_syscall6(TCPCC_HOST_NR_SENDTO, fd,
					 (long)buf, len,
					 TCPCC_HOST_MSG_NOSIGNAL, 0, 0);
	} while (ret == -TCPCC_HOST_EINTR);

	return (ssize_t)ret;
}

ssize_t tcpcc_host_recv_fd(int fd, void *buf, size_t len)
{
	long ret;

	do {
		ret = tcpcc_host_syscall6(TCPCC_HOST_NR_RECVFROM, fd,
					 (long)buf, len, 0, 0, 0);
	} while (ret == -TCPCC_HOST_EINTR);

	return (ssize_t)ret;
}

int tcpcc_host_shutdown(int fd, int how)
{
	long ret;

	do {
		ret = tcpcc_host_syscall2(TCPCC_HOST_NR_SHUTDOWN, fd, how);
	} while (ret == -TCPCC_HOST_EINTR);

	return ret < 0 ? (int)ret : 0;
}

void *__init tcpcc_host_map_anon(size_t len)
{
	long ret = tcpcc_host_syscall6(TCPCC_HOST_NR_MMAP, 0, (long)len,
				       TCPCC_HOST_PROT_READ | TCPCC_HOST_PROT_WRITE,
				       TCPCC_HOST_MAP_PRIVATE | TCPCC_HOST_MAP_ANONYMOUS,
				       -1, 0);

	/* Linux syscalls return -errno in the range [-4095, -1]. */
	if ((unsigned long)ret >= (unsigned long)-4095L)
		return NULL;

	return (void *)ret;
}

u64 tcpcc_host_monotonic_ns(void)
{
	struct tcpcc_host_timespec ts;
	long ret;

	ret = tcpcc_host_syscall2(TCPCC_HOST_NR_CLOCK_GETTIME,
				  TCPCC_HOST_CLOCK_MONOTONIC, (long)&ts);
	if (unlikely(ret < 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 ||
		     ts.tv_nsec >= TCPCC_HOST_NSEC_PER_SEC))
		tcpcc_host_exit(88);

	return (u64)ts.tv_sec * TCPCC_HOST_NSEC_PER_SEC + (u64)ts.tv_nsec;
}

int __init tcpcc_host_timer_create(void)
{
	return (int)tcpcc_host_syscall2(TCPCC_HOST_NR_TIMERFD_CREATE,
					TCPCC_HOST_CLOCK_MONOTONIC, 0);
}

int tcpcc_host_timer_arm(int fd, u64 delta_ns)
{
	struct tcpcc_host_itimerspec spec = { };
	long ret;

	spec.it_value.tv_sec = delta_ns / TCPCC_HOST_NSEC_PER_SEC;
	spec.it_value.tv_nsec = delta_ns % TCPCC_HOST_NSEC_PER_SEC;

	ret = tcpcc_host_syscall4(TCPCC_HOST_NR_TIMERFD_SETTIME, fd, 0,
				  (long)&spec, 0);
	return ret < 0 ? (int)ret : 0;
}

int tcpcc_host_timer_cancel(int fd)
{
	return tcpcc_host_timer_arm(fd, 0);
}

int tcpcc_host_timer_wait(int fd, u64 *expirations)
{
	long ret;

	do {
		ret = tcpcc_host_syscall3(TCPCC_HOST_NR_READ, fd,
					 (long)expirations, sizeof(*expirations));
	} while (ret == -TCPCC_HOST_EINTR);

	if (ret < 0)
		return (int)ret;
	if (ret != sizeof(*expirations))
		return -TCPCC_HOST_EIO;
	return 0;
}

int __init tcpcc_host_event_loop_init(void)
{
	long ret;

	if (tcpcc_host_epoll_fd >= 0)
		return 0;

	ret = tcpcc_host_syscall1(TCPCC_HOST_NR_EPOLL_CREATE1, 0);
	if (ret < 0)
		return (int)ret;

	tcpcc_host_epoll_fd = (int)ret;
	return 0;
}

static int tcpcc_host_event_ctl(int operation, int fd, u64 token,
				u32 interests, bool edge)
{
	struct tcpcc_host_epoll_event event = { .data = token };
	long ret;

	if (tcpcc_host_epoll_fd < 0)
		return -TCPCC_HOST_EIO;
	if (!interests ||
	    interests & ~(TCPCC_HOST_EVENT_READABLE |
			  TCPCC_HOST_EVENT_WRITABLE))
		return -TCPCC_HOST_EINVAL;

	if (interests & TCPCC_HOST_EVENT_READABLE)
		event.events |= TCPCC_HOST_EPOLLIN;
	if (interests & TCPCC_HOST_EVENT_WRITABLE)
		event.events |= TCPCC_HOST_EPOLLOUT;
	/* EPOLLERR and EPOLLHUP are always reported. Ask for peer half-close too. */
	event.events |= TCPCC_HOST_EPOLLRDHUP;
	if (edge)
		event.events |= TCPCC_HOST_EPOLLET;

	ret = tcpcc_host_syscall4(TCPCC_HOST_NR_EPOLL_CTL,
				  tcpcc_host_epoll_fd,
				  operation, fd,
				  (long)&event);
	return ret < 0 ? (int)ret : 0;
}

int tcpcc_host_event_add(int fd, u64 token)
{
	return tcpcc_host_event_add_mask(fd, token,
					 TCPCC_HOST_EVENT_READABLE, false);
}

int tcpcc_host_event_add_edge(int fd, u64 token)
{
	return tcpcc_host_event_add_mask(fd, token,
					 TCPCC_HOST_EVENT_READABLE, true);
}

int tcpcc_host_event_add_mask(int fd, u64 token, u32 interests, bool edge)
{
	return tcpcc_host_event_ctl(TCPCC_HOST_EPOLL_CTL_ADD, fd, token,
				    interests, edge);
}

int tcpcc_host_event_mod_mask(int fd, u64 token, u32 interests, bool edge)
{
	return tcpcc_host_event_ctl(TCPCC_HOST_EPOLL_CTL_MOD, fd, token,
				    interests, edge);
}

int tcpcc_host_event_del(int fd)
{
	long ret;

	if (tcpcc_host_epoll_fd < 0)
		return -TCPCC_HOST_EIO;

	ret = tcpcc_host_syscall4(TCPCC_HOST_NR_EPOLL_CTL,
				  tcpcc_host_epoll_fd,
				  TCPCC_HOST_EPOLL_CTL_DEL, fd, 0);
	return ret < 0 ? (int)ret : 0;
}

static int tcpcc_host_event_wait_timeout(struct tcpcc_host_event *event,
					 int timeout_ms)
{
	struct tcpcc_host_epoll_event host_event;
	u32 events = 0;
	long ret;

	if (tcpcc_host_epoll_fd < 0)
		return -TCPCC_HOST_EIO;

	do {
		ret = tcpcc_host_syscall4(TCPCC_HOST_NR_EPOLL_WAIT,
					  tcpcc_host_epoll_fd,
					  (long)&host_event, 1, timeout_ms);
	} while (ret == -TCPCC_HOST_EINTR);

	if (ret < 0)
		return (int)ret;
	if (!ret)
		return -TCPCC_HOST_ETIMEDOUT;
	if (ret != 1)
		return -TCPCC_HOST_EIO;

	if (host_event.events & TCPCC_HOST_EPOLLIN)
		events |= TCPCC_HOST_EVENT_READABLE;
	if (host_event.events & TCPCC_HOST_EPOLLOUT)
		events |= TCPCC_HOST_EVENT_WRITABLE;
	if (host_event.events & (TCPCC_HOST_EPOLLHUP |
				 TCPCC_HOST_EPOLLRDHUP))
		events |= TCPCC_HOST_EVENT_HANGUP;
	if (host_event.events & TCPCC_HOST_EPOLLERR)
		events |= TCPCC_HOST_EVENT_ERROR;
	if (!events)
		return -TCPCC_HOST_EIO;

	event->token = host_event.data;
	event->events = events;
	return 0;
}

int tcpcc_host_event_wait(struct tcpcc_host_event *event)
{
	return tcpcc_host_event_wait_timeout(event, -1);
}

int __init tcpcc_host_event_selftest(void)
{
	const u64 payload = TCPCC_HOST_EVENT_TEST_TOKEN;
	struct tcpcc_host_event event;
	u64 received = 0;
	int pair[2] = { -1, -1 };
	bool registered = false;
	ssize_t io_ret;
	long host_ret;
	int ret;

	host_ret = tcpcc_host_syscall4(TCPCC_HOST_NR_SOCKETPAIR,
					 TCPCC_HOST_AF_UNIX,
					 TCPCC_HOST_SOCK_STREAM, 0,
					 (long)pair);
	if (host_ret < 0)
		return (int)host_ret;

	ret = tcpcc_host_set_nonblock(pair[0]);
	if (ret)
		goto out;
	ret = tcpcc_host_set_nonblock(pair[1]);
	if (ret)
		goto out;

	ret = tcpcc_host_event_add_mask(pair[0], TCPCC_HOST_EVENT_TEST_TOKEN,
					0, true);
	if (ret != -TCPCC_HOST_EINVAL) {
		ret = -TCPCC_HOST_EIO;
		goto out;
	}
	ret = tcpcc_host_event_add_mask(pair[0], TCPCC_HOST_EVENT_TEST_TOKEN,
					TCPCC_HOST_EVENT_ERROR, true);
	if (ret != -TCPCC_HOST_EINVAL) {
		ret = -TCPCC_HOST_EIO;
		goto out;
	}

	ret = tcpcc_host_event_add_mask(pair[0], TCPCC_HOST_EVENT_TEST_TOKEN,
					TCPCC_HOST_EVENT_WRITABLE, true);
	if (ret)
		goto out;
	registered = true;

	ret = tcpcc_host_event_wait_timeout(&event, 1000);
	if (ret)
		goto out;
	if (event.token != TCPCC_HOST_EVENT_TEST_TOKEN ||
	    !(event.events & TCPCC_HOST_EVENT_WRITABLE)) {
		ret = -TCPCC_HOST_EIO;
		goto out;
	}

	ret = tcpcc_host_event_mod_mask(pair[0], TCPCC_HOST_EVENT_TEST_TOKEN,
					TCPCC_HOST_EVENT_READABLE, true);
	if (ret)
		goto out;

	io_ret = tcpcc_host_write_fd(pair[1], &payload, sizeof(payload));
	if (io_ret != sizeof(payload)) {
		ret = io_ret < 0 ? (int)io_ret : -TCPCC_HOST_EIO;
		goto out;
	}

	ret = tcpcc_host_event_wait_timeout(&event, 1000);
	if (ret)
		goto out;
	if (event.token != TCPCC_HOST_EVENT_TEST_TOKEN ||
	    !(event.events & TCPCC_HOST_EVENT_READABLE)) {
		ret = -TCPCC_HOST_EIO;
		goto out;
	}

	io_ret = tcpcc_host_read_fd(pair[0], &received, sizeof(received));
	if (io_ret != sizeof(received) || received != payload) {
		ret = io_ret < 0 ? (int)io_ret : -TCPCC_HOST_EIO;
		goto out;
	}

	ret = tcpcc_host_close(pair[1]);
	if (ret)
		goto out;
	pair[1] = -1;

	ret = tcpcc_host_event_wait_timeout(&event, 1000);
	if (ret)
		goto out;
	if (event.token != TCPCC_HOST_EVENT_TEST_TOKEN ||
	    !(event.events & TCPCC_HOST_EVENT_HANGUP))
		ret = -TCPCC_HOST_EIO;
out:
	if (registered) {
		int del_ret = tcpcc_host_event_del(pair[0]);

		if (!ret && del_ret)
			ret = del_ret;
	}
	if (pair[0] >= 0) {
		int close_ret = tcpcc_host_close(pair[0]);

		if (!ret && close_ret)
			ret = close_ret;
	}
	if (pair[1] >= 0) {
		int close_ret = tcpcc_host_close(pair[1]);

		if (!ret && close_ret)
			ret = close_ret;
	}

	return ret;
}

void __noreturn tcpcc_host_exit(int status)
{
	(void)tcpcc_host_syscall1(TCPCC_HOST_NR_EXIT_GROUP, status & 0xff);

	/* exit_group() should not return. Keep failure deterministic if it does. */
	for (;;)
		asm volatile("pause" ::: "memory");
}

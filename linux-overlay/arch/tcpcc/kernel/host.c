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

#define TCPCC_HOST_F_GETFL    3
#define TCPCC_HOST_F_SETFL    4
#define TCPCC_HOST_O_NONBLOCK 0x800

#define TCPCC_HOST_PROT_READ      0x1
#define TCPCC_HOST_PROT_WRITE     0x2
#define TCPCC_HOST_MAP_PRIVATE    0x02
#define TCPCC_HOST_MAP_ANONYMOUS  0x20

#define TCPCC_HOST_EPOLLIN       0x001
#define TCPCC_HOST_EPOLL_CTL_ADD 1
#define TCPCC_HOST_EPOLL_CTL_DEL 2

#define TCPCC_HOST_NSEC_PER_SEC 1000000000ULL

struct tcpcc_host_timespec {
	long tv_sec;
	long tv_nsec;
};

struct tcpcc_host_itimerspec {
	struct tcpcc_host_timespec it_interval;
	struct tcpcc_host_timespec it_value;
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

int tcpcc_host_event_add(int fd, u64 token)
{
	struct tcpcc_host_epoll_event event = {
		.events = TCPCC_HOST_EPOLLIN,
		.data = token,
	};
	long ret;

	if (tcpcc_host_epoll_fd < 0)
		return -TCPCC_HOST_EIO;

	ret = tcpcc_host_syscall4(TCPCC_HOST_NR_EPOLL_CTL,
				  tcpcc_host_epoll_fd,
				  TCPCC_HOST_EPOLL_CTL_ADD, fd,
				  (long)&event);
	return ret < 0 ? (int)ret : 0;
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

int tcpcc_host_event_wait(u64 *token)
{
	struct tcpcc_host_epoll_event event;
	long ret;

	if (tcpcc_host_epoll_fd < 0)
		return -TCPCC_HOST_EIO;

	do {
		ret = tcpcc_host_syscall4(TCPCC_HOST_NR_EPOLL_WAIT,
					  tcpcc_host_epoll_fd,
					  (long)&event, 1, -1);
	} while (ret == -TCPCC_HOST_EINTR);

	if (ret < 0)
		return (int)ret;
	if (ret != 1 || !(event.events & TCPCC_HOST_EPOLLIN))
		return -TCPCC_HOST_EIO;

	*token = event.data;
	return 0;
}

void __noreturn tcpcc_host_exit(int status)
{
	(void)tcpcc_host_syscall1(TCPCC_HOST_NR_EXIT_GROUP, status & 0xff);

	/* exit_group() should not return. Keep failure deterministic if it does. */
	for (;;)
		asm volatile("pause" ::: "memory");
}

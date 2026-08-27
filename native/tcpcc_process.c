// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_process.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define TCPCC_EXEC_STATUS_FD 4

static int tcpcc_process_fail(struct tcpcc_control_error *error, int code,
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

static void tcpcc_close(int *fd)
{
	if (*fd >= 0) {
		close(*fd);
		*fd = -1;
	}
}

static int tcpcc_pipe(int descriptors[2])
{
	return pipe2(descriptors, O_CLOEXEC);
}

static int tcpcc_set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static __attribute__((noreturn)) void
tcpcc_child_report_exec_error(int fd, int code)
{
	const unsigned char *cursor = (const unsigned char *)&code;
	size_t written = 0;

	while (written < sizeof(code)) {
		ssize_t result = write(fd, cursor + written,
				       sizeof(code) - written);

		if (result < 0 && errno == EINTR)
			continue;
		if (result <= 0)
			break;
		written += (size_t)result;
	}
	_exit(127);
}

static void tcpcc_child_close_from(int first_fd, rlim_t descriptor_limit)
{
#ifdef SYS_close_range
	if (syscall(SYS_close_range, (unsigned int)first_fd, ~0U, 0) == 0)
		return;
	if (errno != ENOSYS)
		tcpcc_child_report_exec_error(TCPCC_EXEC_STATUS_FD, errno);
#endif
	if (descriptor_limit == RLIM_INFINITY || descriptor_limit > 1048576)
		descriptor_limit = 1048576;
	for (; (rlim_t)first_fd < descriptor_limit; first_fd++)
		close(first_fd);
}

static __attribute__((noreturn)) void
tcpcc_child_exec(const char *kernel_path, int tun_fd,
			 const int requests[2], const int responses[2],
			 const int exec_status[2], pid_t expected_parent,
			 rlim_t descriptor_limit)
{
	char *const arguments[] = { (char *)kernel_path, NULL };
	int code;

	if (setsid() < 0)
		tcpcc_child_report_exec_error(exec_status[1], errno);
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
		tcpcc_child_report_exec_error(exec_status[1], errno);
	if (getppid() != expected_parent)
		tcpcc_child_report_exec_error(exec_status[1], ECHILD);

	if (dup2(requests[0], STDIN_FILENO) < 0 ||
	    dup2(responses[1], STDOUT_FILENO) < 0 ||
	    dup2(tun_fd, TCPCC_HOSTED_TUN_FD) < 0 ||
	    dup2(exec_status[1], TCPCC_EXEC_STATUS_FD) < 0)
		tcpcc_child_report_exec_error(exec_status[1], errno);
	if (fcntl(TCPCC_EXEC_STATUS_FD, F_SETFD, FD_CLOEXEC) < 0)
		tcpcc_child_report_exec_error(TCPCC_EXEC_STATUS_FD, errno);

	tcpcc_child_close_from(TCPCC_EXEC_STATUS_FD + 1, descriptor_limit);
	execv(kernel_path, arguments);
	code = errno;
	tcpcc_child_report_exec_error(TCPCC_EXEC_STATUS_FD, code);
}

static int tcpcc_read_exec_status(int fd, int *exec_error)
{
	unsigned char *cursor = (unsigned char *)exec_error;
	size_t received = 0;

	while (received < sizeof(*exec_error)) {
		ssize_t result = read(fd, cursor + received,
				      sizeof(*exec_error) - received);

		if (result < 0 && errno == EINTR)
			continue;
		if (result < 0)
			return -1;
		if (!result)
			return received ? -1 : 0;
		received += (size_t)result;
	}
	return 1;
}

static int tcpcc_open_pidfd(pid_t pid)
{
#ifdef SYS_pidfd_open
	return (int)syscall(SYS_pidfd_open, pid, 0);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static void tcpcc_reap_failed_child(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
}

int tcpcc_hosted_process_start(struct tcpcc_hosted_process *process,
			       const char *kernel_path, int tun_fd,
			       struct tcpcc_control_error *error)
{
	int requests[2] = { -1, -1 };
	int responses[2] = { -1, -1 };
	int exec_status[2] = { -1, -1 };
	struct rlimit descriptor_limit;
	pid_t expected_parent;
	pid_t child;
	int exec_error = 0;
	int exec_result;

	if (!process || !kernel_path || !kernel_path[0] || tun_fd < 3)
		return tcpcc_process_fail(error, EINVAL,
			"hosted process arguments are invalid");
	*process = (struct tcpcc_hosted_process) {
		.pid = -1,
		.pid_fd = -1,
		.request_fd = -1,
		.response_fd = -1,
	};
	if (getrlimit(RLIMIT_NOFILE, &descriptor_limit) != 0)
		return tcpcc_process_fail(error, errno,
			"getrlimit(RLIMIT_NOFILE) failed: %s", strerror(errno));
	if (tcpcc_pipe(requests) != 0 || tcpcc_pipe(responses) != 0 ||
	    tcpcc_pipe(exec_status) != 0) {
		int code = errno;

		tcpcc_close(&requests[0]);
		tcpcc_close(&requests[1]);
		tcpcc_close(&responses[0]);
		tcpcc_close(&responses[1]);
		tcpcc_close(&exec_status[0]);
		tcpcc_close(&exec_status[1]);
		return tcpcc_process_fail(error, code,
			"hosted process pipe creation failed: %s", strerror(code));
	}

	expected_parent = getpid();
	child = fork();
	if (child < 0) {
		int code = errno;

		tcpcc_close(&requests[0]);
		tcpcc_close(&requests[1]);
		tcpcc_close(&responses[0]);
		tcpcc_close(&responses[1]);
		tcpcc_close(&exec_status[0]);
		tcpcc_close(&exec_status[1]);
		return tcpcc_process_fail(error, code,
			"fork for hosted kernel failed: %s", strerror(code));
	}
	if (!child)
		tcpcc_child_exec(kernel_path, tun_fd, requests, responses,
				 exec_status, expected_parent,
				 descriptor_limit.rlim_cur);

	tcpcc_close(&requests[0]);
	tcpcc_close(&responses[1]);
	tcpcc_close(&exec_status[1]);
	exec_result = tcpcc_read_exec_status(exec_status[0], &exec_error);
	tcpcc_close(&exec_status[0]);
	if (exec_result != 0) {
		int code = exec_result < 0 ? EIO : exec_error;

		tcpcc_close(&requests[1]);
		tcpcc_close(&responses[0]);
		tcpcc_reap_failed_child(child);
		return tcpcc_process_fail(error, code,
			"exec of hosted kernel %s failed: %s", kernel_path,
			strerror(code));
	}

	if (tcpcc_set_nonblock(requests[1]) != 0 ||
	    tcpcc_set_nonblock(responses[0]) != 0) {
		int code = errno;

		kill(child, SIGKILL);
		tcpcc_reap_failed_child(child);
		tcpcc_close(&requests[1]);
		tcpcc_close(&responses[0]);
		return tcpcc_process_fail(error, code,
			"setting hosted control pipes nonblocking failed: %s",
			strerror(code));
	}

	process->pid = child;
	process->pid_fd = tcpcc_open_pidfd(child);
	process->request_fd = requests[1];
	process->response_fd = responses[0];
	if (error) {
		error->code = 0;
		error->message[0] = '\0';
	}
	return 0;
}

int tcpcc_hosted_process_signal(const struct tcpcc_hosted_process *process,
				int signal_number,
				struct tcpcc_control_error *error)
{
	if (!process || process->pid <= 0 || signal_number < 0)
		return tcpcc_process_fail(error, EINVAL,
			"hosted process signal arguments are invalid");
	if (kill(process->pid, signal_number) != 0)
		return tcpcc_process_fail(error, errno,
			"signal %d to hosted process %d failed: %s",
			signal_number, process->pid, strerror(errno));
	return 0;
}

int tcpcc_hosted_process_wait(struct tcpcc_hosted_process *process,
			      int *wait_status,
			      struct tcpcc_control_error *error)
{
	pid_t result;
	int status;

	if (!process || process->pid <= 0)
		return tcpcc_process_fail(error, EINVAL,
			"hosted process is not running");
	do {
		result = waitpid(process->pid, &status, 0);
	} while (result < 0 && errno == EINTR);
	if (result < 0)
		return tcpcc_process_fail(error, errno,
			"waitpid for hosted process %d failed: %s",
			process->pid, strerror(errno));
	process->pid = -1;
	tcpcc_close(&process->pid_fd);
	if (wait_status)
		*wait_status = status;
	return 0;
}

void tcpcc_hosted_process_close_channels(struct tcpcc_hosted_process *process)
{
	if (!process)
		return;
	tcpcc_close(&process->request_fd);
	tcpcc_close(&process->response_fd);
}

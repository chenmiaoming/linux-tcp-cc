// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int wait_for_child(pid_t child)
{
	int status;
	pid_t result;

	do {
		result = waitpid(child, &status, 0);
	} while (result < 0 && errno == EINTR);
	if (result < 0) {
		perror("waitpid");
		return 1;
	}
	if (WIFSIGNALED(status)) {
		fprintf(stderr, "tcpcc terminated by signal %d\n", WTERMSIG(status));
		return 1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "tcpcc exited with status %d\n",
			WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int output[2];
	pid_t child;

	if (argc != 2) {
		fprintf(stderr, "usage: %s /path/to/tcpcc\n", argv[0]);
		return 2;
	}
	if (pipe(output) != 0) {
		perror("pipe");
		return 1;
	}

	/* No reader survives: the first stdout/stderr write sees EPIPE/SIGPIPE. */
	close(output[0]);
	child = fork();
	if (child < 0) {
		perror("fork");
		close(output[1]);
		return 1;
	}
	if (!child) {
		if (dup2(output[1], STDOUT_FILENO) < 0 ||
		    dup2(output[1], STDERR_FILENO) < 0)
			_exit(126);
		close(output[1]);
		execl(argv[1], argv[1], "--help", (char *)NULL);
		_exit(127);
	}
	close(output[1]);
	return wait_for_child(child);
}

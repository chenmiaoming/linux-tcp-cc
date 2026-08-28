// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_process.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int read_exact(int fd, void *buffer, size_t length)
{
	unsigned char *cursor = buffer;
	size_t received = 0;

	while (received < length) {
		ssize_t result = read(fd, cursor + received, length - received);

		if (result < 0 && errno == EINTR)
			continue;
		if (result <= 0)
			return -1;
		received += (size_t)result;
	}
	return 0;
}

static int write_exact(int fd, const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;
	size_t written = 0;

	while (written < length) {
		ssize_t result = write(fd, cursor + written, length - written);

		if (result < 0 && errno == EINTR)
			continue;
		if (result <= 0)
			return -1;
		written += (size_t)result;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct tcpcc_control_request request;
	struct tcpcc_control_response response = {
		.magic = TCPCC_CONTROL_MAGIC,
		.version = TCPCC_CONTROL_VERSION,
	};
	struct tcpcc_control_hello hello = {
		.control_version = TCPCC_CONTROL_VERSION,
	};

	if (argc != 2 || strcmp(argv[1], "--memory-mib=512"))
		return 80;
	if (fcntl(TCPCC_HOSTED_TUN_FD, F_GETFD) < 0)
		return 81;
	errno = 0;
	if (fcntl(4, F_GETFD) >= 0 || errno != EBADF)
		return 82;
	if (read_exact(STDIN_FILENO, &request, sizeof(request)) != 0)
		return 83;
	if (request.magic != TCPCC_CONTROL_MAGIC ||
	    request.version != TCPCC_CONTROL_VERSION ||
	    request.op != TCPCC_CONTROL_HELLO || request.length)
		return 84;
	response.op = request.op;
	response.length = sizeof(hello);
	memcpy(response.data, &hello, sizeof(hello));
	if (write_exact(STDOUT_FILENO, &response, sizeof(response)) != 0)
		return 85;
	return 0;
}

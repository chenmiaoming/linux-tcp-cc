// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_control.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *message)
{
	fprintf(stderr, "native control test: %s\n", message);
	exit(1);
}

static void write_fragmented(int fd, const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;
	size_t offset = 0;

	while (offset < length) {
		size_t chunk = length - offset > 17 ? 17 : length - offset;
		ssize_t written = write(fd, cursor + offset, chunk);

		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0)
			_exit(91);
		offset += (size_t)written;
	}
}

static void fake_hosted_kernel(int request_fd, int response_fd)
{
	struct tcpcc_control_request request;
	struct tcpcc_control_response response = { 0 };
	struct tcpcc_control_hello hello = {
		.control_version = TCPCC_CONTROL_VERSION,
		.feature_bits = TCPCC_CONTROL_FEATURE_BRIDGE_RESULT,
		.session_limit = 8,
		.bridge_buffer_limit = 16 * 1024,
		.bridge_total_buffer_limit = 256 * 1024,
	};
	unsigned char *cursor = (unsigned char *)&request;
	size_t received = 0;

	while (received < sizeof(request)) {
		ssize_t result = read(request_fd, cursor + received,
				      sizeof(request) - received);

		if (result < 0 && errno == EINTR)
			continue;
		if (result <= 0)
			_exit(92);
		received += (size_t)result;
	}
	if (request.magic != TCPCC_CONTROL_MAGIC ||
	    request.version != TCPCC_CONTROL_VERSION ||
	    request.op != TCPCC_CONTROL_HELLO || request.length)
		_exit(93);

	memcpy(hello.linux_release, "6.18.45-tcpcc", 14);
	response.magic = TCPCC_CONTROL_MAGIC;
	response.version = TCPCC_CONTROL_VERSION;
	response.op = request.op;
	response.length = sizeof(hello);
	memcpy(response.data, &hello, sizeof(hello));
	write_fragmented(response_fd, &response, sizeof(response));
	_exit(0);
}

int main(void)
{
	struct tcpcc_control_client client;
	struct tcpcc_control_response response;
	struct tcpcc_control_error error;
	struct tcpcc_control_hello hello;
	int requests[2];
	int responses[2];
	int status;
	pid_t child;

	if (pipe(requests) != 0 || pipe(responses) != 0)
		fail("pipe creation failed");
	child = fork();
	if (child < 0)
		fail("fork failed");
	if (!child) {
		close(requests[1]);
		close(responses[0]);
		fake_hosted_kernel(requests[0], responses[1]);
	}

	close(requests[0]);
	close(responses[1]);
	if (tcpcc_control_client_init(&client, requests[1], responses[0], 2000,
				      &error) != 0)
		fail(error.message);
	if (tcpcc_control_transact(&client, TCPCC_CONTROL_HELLO, 0, 0, 0,
				   NULL, 0, &response, &error) != 0)
		fail(error.message);
	if (response.status || response.length != sizeof(hello))
		fail("hello response status or length is invalid");
	memcpy(&hello, response.data, sizeof(hello));
	if (hello.control_version != TCPCC_CONTROL_VERSION ||
	    hello.feature_bits != TCPCC_CONTROL_FEATURE_BRIDGE_RESULT ||
	    strcmp(hello.linux_release, "6.18.45-tcpcc"))
		fail("hello response contents are invalid");

	close(requests[1]);
	close(responses[0]);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		fail("fake hosted kernel did not exit cleanly");
	puts("native control ABI test passed");
	return 0;
}

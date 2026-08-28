// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_process.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *message)
{
	fprintf(stderr, "native process test: %s\n", message);
	exit(1);
}

int main(int argc, char **argv)
{
	struct tcpcc_hosted_process process;
	struct tcpcc_control_client client;
	struct tcpcc_control_response response;
	struct tcpcc_control_error error;
	int tun_fd;
	int status;

	if (argc != 2)
		fail("expected the fake hosted-kernel path");
	tun_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	if (tun_fd < 3)
		fail("fake TUN fd creation failed");
	if (tcpcc_hosted_process_start(&process, argv[1], 512, tun_fd,
				       &error) != 0)
		fail(error.message);
	close(tun_fd);

	if (tcpcc_hosted_process_signal(&process, 0, &error) != 0)
		fail(error.message);
	if (tcpcc_control_client_init(&client, process.request_fd,
				      process.response_fd, 2000, &error) != 0)
		fail(error.message);
	if (tcpcc_control_transact(&client, TCPCC_CONTROL_HELLO, 0, 0, 0,
				   NULL, 0, &response, &error) != 0)
		fail(error.message);
	if (response.status || response.length != sizeof(struct tcpcc_control_hello))
		fail("fake hosted handshake failed");

	tcpcc_hosted_process_close_channels(&process);
	if (tcpcc_hosted_process_wait(&process, &status, &error) != 0)
		fail(error.message);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		fail("fake hosted process did not exit cleanly");
	puts("native hosted-process test passed");
	return 0;
}

// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_process.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *message)
{
	fprintf(stderr, "native process test: %s\n", message);
	exit(1);
}

static void test_process_validation(const char *kernel_path)
{
	struct tcpcc_hosted_process process;
	struct tcpcc_control_error error;
	int tun_fd;

	tun_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	if (tun_fd < 3)
		fail("fake TUN fd creation failed");

	if (tcpcc_hosted_process_start(NULL, kernel_path, 512, tun_fd, &error) == 0 ||
	    error.code != EINVAL)
		fail("process start did not reject NULL process pointer");

	if (tcpcc_hosted_process_start(&process, NULL, 512, tun_fd, &error) == 0 ||
	    error.code != EINVAL)
		fail("process start did not reject NULL kernel path");

	if (tcpcc_hosted_process_start(&process, "", 512, tun_fd, &error) == 0 ||
	    error.code != EINVAL)
		fail("process start did not reject empty kernel path");

	if (tcpcc_hosted_process_start(&process, kernel_path, 127, tun_fd, &error) == 0 ||
	    error.code != EINVAL)
		fail("process start did not reject memory_mib < 128");

	if (tcpcc_hosted_process_start(&process, kernel_path, 512, 2, &error) == 0 ||
	    error.code != EINVAL)
		fail("process start did not reject invalid tun_fd < 3");

	close(tun_fd);
}

static void test_demand_backed_mmap(void)
{
	size_t size = 512 * 1024 * 1024;
	void *arena;

	if (MAP_NORESERVE != 0x4000)
		fail("MAP_NORESERVE constant value mismatch");

	arena = mmap(NULL, size, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (arena == MAP_FAILED)
		fail("demand-backed mmap failed");

	((char *)arena)[0] = (char)0xa5;
	if (((char *)arena)[0] != (char)0xa5)
		fail("demand-backed arena readback mismatch");

	if (munmap(arena, size) != 0)
		fail("munmap failed");
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

	test_process_validation(argv[1]);
	test_demand_backed_mmap();
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

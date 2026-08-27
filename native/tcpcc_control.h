/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TCPCC_NATIVE_CONTROL_H
#define TCPCC_NATIVE_CONTROL_H

#include <stddef.h>
#include <stdint.h>

#include <asm/tcpcc_control_abi.h>

struct tcpcc_control_client {
	int request_fd;
	int response_fd;
	int timeout_ms;
};

struct tcpcc_control_error {
	int code;
	char message[256];
};

int tcpcc_control_client_init(struct tcpcc_control_client *client,
			      int request_fd, int response_fd,
			      int timeout_ms,
			      struct tcpcc_control_error *error);

int tcpcc_control_transact(struct tcpcc_control_client *client,
			   uint16_t operation, int32_t handle,
			   uint32_t arg0, uint32_t arg1,
			   const void *data, uint32_t length,
			   struct tcpcc_control_response *response,
			   struct tcpcc_control_error *error);

#endif /* TCPCC_NATIVE_CONTROL_H */

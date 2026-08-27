/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_BRIDGE_H
#define _ASM_TCPCC_BRIDGE_H

#include <linux/types.h>
#include <asm/tcpcc_control_abi.h>

/* Eight sessions x two 16 KiB directions: 256 KiB of fixed data storage. */
#define TCPCC_BRIDGE_SESSION_LIMIT       8U
#define TCPCC_BRIDGE_BUFFER_LIMIT        (16U * 1024U)
#define TCPCC_BRIDGE_TOTAL_BUFFER_LIMIT  \
	(TCPCC_BRIDGE_SESSION_LIMIT * 2U * TCPCC_BRIDGE_BUFFER_LIMIT)
/* Linux doubles SO_SNDBUF/SO_RCVBUF requests; request 32 KiB for 64 KiB. */
#define TCPCC_BRIDGE_HOST_SOCKET_BUFFER_REQUEST (32U * 1024U)
#define TCPCC_BRIDGE_HOST_SOCKET_BUFFER_LIMIT   (64U * 1024U)
#define TCPCC_BRIDGE_RUNTIME_SLOT_BASE   2U

/* Positive s32 handle: [30:4] generation, [3:0] one-based session slot. */
#define TCPCC_BRIDGE_HANDLE_SLOT_BITS    4U
#define TCPCC_BRIDGE_HANDLE_SLOT_MASK    0x0fU
#define TCPCC_BRIDGE_HANDLE_GENERATION_MASK 0x07ffffffU

struct socket;

int tcpcc_bridge_start(struct socket *public_sock, __be32 backend_address,
		       __be16 backend_port, int *handle);
int tcpcc_bridge_cancel_session(int handle);
int tcpcc_bridge_join(int handle, unsigned long timeout,
		      struct tcpcc_bridge_result *result);
int tcpcc_bridge_join_result(int handle, unsigned long timeout,
			     struct tcpcc_bridge_result *result);
int tcpcc_bridge_try_join_result(int handle,
				 struct tcpcc_bridge_result *result);
int tcpcc_bridge_set_completion_notifier(void (*notify)(void *), void *data);
void tcpcc_bridge_clear_completion_notifier(void (*notify)(void *), void *data);
bool tcpcc_bridge_active(void);
void tcpcc_bridge_cancel(void);

#endif /* _ASM_TCPCC_BRIDGE_H */

/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_BRIDGE_H
#define _ASM_TCPCC_BRIDGE_H

#include <linux/types.h>
#include <asm/tcpcc_control_abi.h>

/*
 * Handles reserve twelve low bits for a dynamically allocated slot.  This is
 * an encoding ceiling, not the supported/default admission limit; capacity is
 * selected by the service configuration and validated in CI.
 */
#define TCPCC_BRIDGE_SESSION_LIMIT       4095U
/* Lazy direction buffers share this aggregate dispatcher-owned budget. */
#define TCPCC_BRIDGE_BUFFER_LIMIT        (16U * 1024U)
#define TCPCC_BRIDGE_TOTAL_BUFFER_LIMIT  (256U * 1024U)
/* Linux doubles SO_SNDBUF/SO_RCVBUF requests; request 32 KiB for 64 KiB. */
#define TCPCC_BRIDGE_HOST_SOCKET_BUFFER_REQUEST (32U * 1024U)
#define TCPCC_BRIDGE_HOST_SOCKET_BUFFER_LIMIT   (64U * 1024U)
#define TCPCC_BRIDGE_RUNTIME_SLOT_BASE   2U

/* Positive s32 handle: [30:12] generation, [11:0] one-based flow slot. */
#define TCPCC_BRIDGE_HANDLE_SLOT_BITS    12U
#define TCPCC_BRIDGE_HANDLE_SLOT_MASK    0x0fffU
#define TCPCC_BRIDGE_HANDLE_GENERATION_MASK 0x0007ffffU

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

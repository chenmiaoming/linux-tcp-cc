/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_BRIDGE_H
#define _ASM_TCPCC_BRIDGE_H

#include <linux/types.h>

/* Eight sessions x two 16 KiB directions: 256 KiB of fixed data storage. */
#define TCPCC_BRIDGE_SESSION_LIMIT       8U
#define TCPCC_BRIDGE_BUFFER_LIMIT        (16U * 1024U)
#define TCPCC_BRIDGE_TOTAL_BUFFER_LIMIT  \
	(TCPCC_BRIDGE_SESSION_LIMIT * 2U * TCPCC_BRIDGE_BUFFER_LIMIT)
#define TCPCC_BRIDGE_RUNTIME_SLOT_BASE   2U

/* Positive s32 handle: [30:4] generation, [3:0] one-based session slot. */
#define TCPCC_BRIDGE_HANDLE_SLOT_BITS    4U
#define TCPCC_BRIDGE_HANDLE_SLOT_MASK    0x0fU
#define TCPCC_BRIDGE_HANDLE_GENERATION_MASK 0x07ffffffU

struct socket;

struct tcpcc_bridge_result {
	u64 token;
	u64 public_to_backend_bytes;
	u64 backend_to_public_bytes;
	u32 buffer_limit;
	u32 total_buffer_limit;
	u32 terminal_events;
	u32 host_send_eagain;
	u32 host_partial_writes;
	u32 host_recv_eagain;
	u32 session_limit;
	s32 status;
	u32 reserved[2];
};

int tcpcc_bridge_start(struct socket *public_sock, __be32 backend_address,
		       __be16 backend_port, int *handle);
int tcpcc_bridge_join(int handle, unsigned long timeout,
		      struct tcpcc_bridge_result *result);
bool tcpcc_bridge_active(void);
void tcpcc_bridge_cancel(void);

#endif /* _ASM_TCPCC_BRIDGE_H */

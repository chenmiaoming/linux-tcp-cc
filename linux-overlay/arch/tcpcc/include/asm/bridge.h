/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_BRIDGE_H
#define _ASM_TCPCC_BRIDGE_H

#include <linux/types.h>

#define TCPCC_BRIDGE_HANDLE       1
#define TCPCC_BRIDGE_BUFFER_LIMIT (16U * 1024U)

struct socket;

struct tcpcc_bridge_result {
	u64 token;
	u64 public_to_backend_bytes;
	u64 backend_to_public_bytes;
	u32 buffer_limit;
	u32 terminal_events;
	s32 status;
	u32 reserved;
};

int tcpcc_bridge_start(struct socket *public_sock, __be32 backend_address,
		       __be16 backend_port, int *handle);
int tcpcc_bridge_join(int handle, unsigned long timeout,
		      struct tcpcc_bridge_result *result);
bool tcpcc_bridge_active(void);
void tcpcc_bridge_cancel(void);

#endif /* _ASM_TCPCC_BRIDGE_H */

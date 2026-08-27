/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_SERVICE_H
#define _ASM_TCPCC_SERVICE_H

#include <linux/types.h>
#include <asm/tcpcc_control_abi.h>

struct socket;

#define TCPCC_SERVICE_HANDLE 1
#define TCPCC_SERVICE_MAX_ACCEPT_BATCH 64U

int tcpcc_service_start(struct socket *listener,
			const struct tcpcc_control_service_config *config,
			int *handle);
int tcpcc_service_drain(int handle, unsigned long timeout,
			struct tcpcc_control_service_stats *stats);
int tcpcc_service_get_stats(int handle,
			    struct tcpcc_control_service_stats *stats);
int tcpcc_service_stop(int handle, unsigned long timeout,
		       struct tcpcc_control_service_stats *stats);
bool tcpcc_service_active(void);
void tcpcc_service_cancel(void);

#endif /* _ASM_TCPCC_SERVICE_H */

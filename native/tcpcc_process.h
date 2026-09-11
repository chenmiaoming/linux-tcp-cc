/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TCPCC_NATIVE_PROCESS_H
#define TCPCC_NATIVE_PROCESS_H

#include <sys/types.h>

#include "tcpcc_control.h"

#define TCPCC_HOSTED_TUN_FD 3
#define TCPCC_HOSTED_DEFAULT_MEMORY_MIB 128UL
#define TCPCC_HOSTED_MINIMUM_MEMORY_MIB 32UL

/*
 * The installed CLI consumes --tcp-wmem-max-kib and passes the selected value
 * to the hosted image through this private process-launch environment slot.
 * A missing value means the hosted kernel should apply its RAM-sized auto
 * policy.  The byte value must fit the signed int used by tcp_wmem[].
 */
#define TCPCC_TCP_WMEM_MAX_KIB_ENV "TCPCC_TCP_WMEM_MAX_KIB"
#define TCPCC_TCP_WMEM_MAX_KIB_MINIMUM 64UL
#define TCPCC_TCP_WMEM_MAX_KIB_LIMIT 2097151UL

struct tcpcc_hosted_process {
	pid_t pid;
	int pid_fd;
	int request_fd;
	int response_fd;
};

int tcpcc_hosted_process_start(struct tcpcc_hosted_process *process,
			       const char *kernel_path,
			       unsigned long memory_mib, int tun_fd,
			       struct tcpcc_control_error *error);

int tcpcc_hosted_process_signal(const struct tcpcc_hosted_process *process,
				int signal_number,
				struct tcpcc_control_error *error);

int tcpcc_hosted_process_wait(struct tcpcc_hosted_process *process,
			      int *wait_status,
			      struct tcpcc_control_error *error);

void tcpcc_hosted_process_close_channels(struct tcpcc_hosted_process *process);

#endif /* TCPCC_NATIVE_PROCESS_H */

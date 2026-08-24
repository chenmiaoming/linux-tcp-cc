/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_L3NET_H
#define _ASM_TCPCC_L3NET_H

#include <linux/types.h>

struct tcpcc_l3_stats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 rx_dropped;
	u64 rx_errors;
	u64 tx_packets;
	u64 tx_bytes;
	u64 tx_dropped;
	u64 tx_errors;
};

int tcpcc_l3_attach(int host_fd, u32 ipv4_addr, u32 prefix_len,
		    int *ifindex);
int tcpcc_l3_get_stats(struct tcpcc_l3_stats *stats);
int tcpcc_l3_validate(void);
void tcpcc_l3_teardown(void);

#endif /* _ASM_TCPCC_L3NET_H */

/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TCPCC_NATIVE_CONFIG_H
#define TCPCC_NATIVE_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

struct tcpcc_file_forward {
	char *listen;
	char *backend;
};

struct tcpcc_file_config {
	char *cc;
	char *kernel;
	char *firewall_backend;
	char *iptables_variant;
	char *tun_name;
	char *tun_host_address;
	char *tun_guest_address;
	struct tcpcc_file_forward *forwards;
	size_t forward_count;
	unsigned long memory_mib;
	unsigned long tcp_wmem_max_kib;
	unsigned long backlog;
	unsigned long max_connections;
	double shutdown_grace_period;
	bool has_memory_mib;
	bool has_tcp_wmem_max_kib;
	bool has_backlog;
	bool has_max_connections;
	bool has_shutdown_grace_period;
};

int tcpcc_config_load(const char *path, struct tcpcc_file_config *config,
		      char *error, size_t error_size);
void tcpcc_config_free(struct tcpcc_file_config *config);

#endif /* TCPCC_NATIVE_CONFIG_H */

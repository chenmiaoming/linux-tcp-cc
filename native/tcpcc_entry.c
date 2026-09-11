// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_process.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int tcpcc_cli_main(int argc, char **argv);

static void tcpcc_entry_usage(FILE *stream)
{
	fprintf(stream,
		"usage: tcpcc --listen IP:PORT --backend 127.0.0.1:PORT --cc NAME [options]\n"
		"\n"
		"Terminate public TCP inside the hosted Linux stack and bridge it to\n"
		"one local backend. The installed command has no Python dependency.\n"
		"\n"
		"  --kernel PATH                 hosted vmlinux (or TCPCC_KERNEL)\n"
		"  --memory-mib MIB              hosted memory, minimum 32 (default 128)\n"
		"  --tcp-wmem-max-kib KIB        hosted TCP send autotune ceiling (default auto)\n"
		"  --firewall-backend NAME       nft-lib, nft-exec, or iptables\n"
		"  --iptables-variant NAME       iptables, iptables-nft, or iptables-legacy\n"
		"  --tun-name NAME               exclusive nonpersistent TUN name\n"
		"  --tun-host-address IP         host-side point-to-point address\n"
		"  --tun-guest-address IP        hosted point-to-point address\n"
		"  --backlog N                   listener backlog (default 128)\n"
		"  --max-connections N           0 means no policy limit (default 0)\n"
		"  --shutdown-grace-period SEC   graceful drain timeout (default 5)\n");
}

static int tcpcc_entry_parse_unsigned(const char *text, unsigned long minimum,
				      unsigned long maximum,
				      unsigned long *value)
{
	char *end = NULL;
	unsigned long parsed;

	if (!text || !text[0] || text[0] < '0' || text[0] > '9')
		return -1;
	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !end || *end || parsed < minimum || parsed > maximum)
		return -1;
	*value = parsed;
	return 0;
}

static int tcpcc_entry_error(const char *message)
{
	fprintf(stderr, "tcpcc: error: %s\n", message);
	return 1;
}

int main(int argc, char **argv)
{
	char **filtered;
	unsigned long value;
	bool tcp_wmem_seen = false;
	bool help = false;
	int filtered_argc = 1;
	int index;

	if (unsetenv(TCPCC_TCP_WMEM_MAX_KIB_ENV) != 0)
		return tcpcc_entry_error("clearing internal tcp_wmem launch state failed");
	filtered = calloc((size_t)argc + 1, sizeof(*filtered));
	if (!filtered)
		return tcpcc_entry_error("allocating argument vector failed");
	filtered[0] = argv[0];

	for (index = 1; index < argc; index++) {
		const char *argument = argv[index];
		const char *value_text = NULL;
		bool consume_next = false;

		if (!strcmp(argument, "-h") || !strcmp(argument, "--help"))
			help = true;

		if (!strcmp(argument, "--memory-mib")) {
			if (index + 1 >= argc) {
				free(filtered);
				return tcpcc_entry_error("--memory-mib requires an argument");
			}
			value_text = argv[index + 1];
			if (tcpcc_entry_parse_unsigned(value_text,
						       TCPCC_HOSTED_MINIMUM_MEMORY_MIB,
						       ~0UL, &value)) {
				free(filtered);
				return tcpcc_entry_error("hosted memory must be at least 32 MiB");
			}
		} else if (!strncmp(argument, "--memory-mib=", 13)) {
			value_text = argument + 13;
			if (tcpcc_entry_parse_unsigned(value_text,
						       TCPCC_HOSTED_MINIMUM_MEMORY_MIB,
						       ~0UL, &value)) {
				free(filtered);
				return tcpcc_entry_error("hosted memory must be at least 32 MiB");
			}
		}

		if (!strcmp(argument, "--tcp-wmem-max-kib")) {
			if (index + 1 >= argc) {
				free(filtered);
				return tcpcc_entry_error("--tcp-wmem-max-kib requires an argument");
			}
			value_text = argv[index + 1];
			consume_next = true;
		} else if (!strncmp(argument, "--tcp-wmem-max-kib=", 20)) {
			value_text = argument + 20;
		}
		if (value_text &&
		    (!strcmp(argument, "--tcp-wmem-max-kib") ||
		     !strncmp(argument, "--tcp-wmem-max-kib=", 20))) {
			char canonical[32];

			if (tcp_wmem_seen) {
				free(filtered);
				return tcpcc_entry_error("--tcp-wmem-max-kib may be specified only once");
			}
			if (tcpcc_entry_parse_unsigned(value_text,
						       TCPCC_TCP_WMEM_MAX_KIB_MINIMUM,
						       TCPCC_TCP_WMEM_MAX_KIB_LIMIT,
						       &value)) {
				free(filtered);
				return tcpcc_entry_error("tcp_wmem maximum must be from 64 through 2097151 KiB");
			}
			snprintf(canonical, sizeof(canonical), "%lu", value);
			if (setenv(TCPCC_TCP_WMEM_MAX_KIB_ENV, canonical, 1) != 0) {
				free(filtered);
				return tcpcc_entry_error("setting internal tcp_wmem launch state failed");
			}
			tcp_wmem_seen = true;
			if (consume_next)
				index++;
			continue;
		}

		filtered[filtered_argc++] = argv[index];
	}
	filtered[filtered_argc] = NULL;

	if (help) {
		tcpcc_entry_usage(stdout);
		free(filtered);
		return 0;
	}

	index = tcpcc_cli_main(filtered_argc, filtered);
	free(filtered);
	return index;
}

// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_config.h"
#include "tcpcc_process.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TCPCC_TCP_WMEM_OPTION "--tcp-wmem-max-kib="
#define TCPCC_CONFIG_OPTION "--config="

int tcpcc_cli_main(int argc, char **argv);

static void tcpcc_entry_usage(FILE *stream)
{
	fprintf(stream,
		"usage: tcpcc --config FILE [--check]\n"
		"       tcpcc --forward LISTEN=127.0.0.1:PORT [--forward LISTEN=127.0.0.1:PORT ...] --cc NAME [options]\n"
		"\n"
		"Terminate public TCP inside the hosted Linux stack and forward each\n"
		"public listener to its fixed local backend. Repeat --forward to add\n"
		"listeners. All public listeners in one process must use one address\n"
		"family and distinct ports.\n"
		"The installed command has no Python dependency.\n"
		"\n"
		"  --config FILE                  load versioned TOML service configuration\n"
		"  --forward LISTEN=BACKEND      fixed public-listener/backend mapping (repeatable)\n"
		"  --check                        validate host prerequisites without mutation\n"
		"  --kernel PATH                 hosted vmlinux (or TCPCC_KERNEL)\n"
		"  --memory-mib MIB              hosted memory, minimum %lu (default %lu)\n"
		"  --tcp-wmem-max-kib KIB        hosted TCP send autotune ceiling (default auto)\n"
		"  --firewall-backend NAME       nft-lib, nft-exec, or iptables\n"
		"  --iptables-variant NAME       iptables, iptables-nft, or iptables-legacy\n"
		"  --tun-name NAME               exclusive nonpersistent TUN name\n"
		"  --tun-host-address IP         host-side point-to-point address\n"
		"  --tun-guest-address IP        hosted point-to-point address\n"
		"  --backlog N                   listener backlog (default 128)\n"
		"  --max-connections N           0 means no policy limit (default 0)\n"
		"  --shutdown-grace-period SEC   graceful drain timeout (default 5)\n",
		TCPCC_HOSTED_MINIMUM_MEMORY_MIB,
		TCPCC_HOSTED_DEFAULT_MEMORY_MIB);
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

static int tcpcc_entry_memory_error(void)
{
	fprintf(stderr, "tcpcc: error: hosted memory must be at least %lu MiB\n",
		TCPCC_HOSTED_MINIMUM_MEMORY_MIB);
	return 1;
}

static int tcpcc_entry_ignore_sigpipe(void)
{
	struct sigaction action = { .sa_handler = SIG_IGN };

	if (sigemptyset(&action.sa_mask) != 0 ||
	    sigaction(SIGPIPE, &action, NULL) != 0)
		return -1;
	return 0;
}

static int tcpcc_entry_set_tcp_wmem(unsigned long value)
{
	char canonical[32];

	if (value < TCPCC_TCP_WMEM_MAX_KIB_MINIMUM ||
	    value > TCPCC_TCP_WMEM_MAX_KIB_LIMIT)
		return tcpcc_entry_error("tcp_wmem maximum must be from 64 through 2097151 KiB");
	snprintf(canonical, sizeof(canonical), "%lu", value);
	if (setenv(TCPCC_TCP_WMEM_MAX_KIB_ENV, canonical, 1) != 0)
		return tcpcc_entry_error("setting internal tcp_wmem launch state failed");
	return 0;
}

static int tcpcc_entry_find_config(int argc, char **argv, const char **path,
				   bool *help)
{
	int index;

	*path = NULL;
	*help = false;
	for (index = 1; index < argc; index++) {
		const char *argument = argv[index];
		const char *candidate = NULL;

		if (!strcmp(argument, "-h") || !strcmp(argument, "--help"))
			*help = true;
		if (!strcmp(argument, "--config")) {
			if (index + 1 >= argc)
				return tcpcc_entry_error("--config requires an argument");
			candidate = argv[++index];
		} else if (!strncmp(argument, TCPCC_CONFIG_OPTION,
				   sizeof(TCPCC_CONFIG_OPTION) - 1)) {
			candidate = argument + sizeof(TCPCC_CONFIG_OPTION) - 1;
		}
		if (candidate) {
			if (!candidate[0])
				return tcpcc_entry_error("--config requires a non-empty path");
			if (*path)
				return tcpcc_entry_error("--config may be specified only once");
			*path = candidate;
		}
	}
	return 0;
}

static int tcpcc_entry_validate_config_argv(int argc, char **argv)
{
	int index;

	for (index = 1; index < argc; index++) {
		const char *argument = argv[index];

		if (!strcmp(argument, "--check") || !strcmp(argument, "-h") ||
		    !strcmp(argument, "--help"))
			continue;
		if (!strcmp(argument, "--config")) {
			index++;
			continue;
		}
		if (!strncmp(argument, TCPCC_CONFIG_OPTION,
				   sizeof(TCPCC_CONFIG_OPTION) - 1))
			continue;
		return tcpcc_entry_error("--config cannot be combined with direct service options");
	}
	return 0;
}

static int tcpcc_entry_append(char **arguments, int *count, size_t capacity,
			      const char *format, ...)
{
	va_list values;
	char *argument = NULL;

	if ((size_t)*count + 1 >= capacity)
		return -1;
	va_start(values, format);
	if (vasprintf(&argument, format, values) < 0)
		argument = NULL;
	va_end(values);
	if (!argument)
		return -1;
	arguments[(*count)++] = argument;
	arguments[*count] = NULL;
	return 0;
}

static void tcpcc_entry_free_generated(char **arguments, int count)
{
	int index;

	if (!arguments)
		return;
	for (index = 1; index < count; index++)
		free(arguments[index]);
	free(arguments);
}

static int tcpcc_entry_build_config_argv(const char *argv0,
					 const struct tcpcc_file_config *config,
					 bool check, char ***result_argv,
					 int *result_argc)
{
	size_t capacity;
	char **arguments;
	int count = 1;
	size_t index;

	if (config->forward_count > (size_t)INT_MAX - 32)
		return tcpcc_entry_error("configuration contains too many forwards");
	capacity = config->forward_count + 32;
	arguments = calloc(capacity, sizeof(*arguments));
	if (!arguments)
		return tcpcc_entry_error("allocating configuration argument vector failed");
	arguments[0] = (char *)argv0;

	if ((check && tcpcc_entry_append(arguments, &count, capacity, "%s", "--check")) ||
	    tcpcc_entry_append(arguments, &count, capacity, "--cc=%s", config->cc))
		goto allocation_error;
	for (index = 0; index < config->forward_count; index++) {
		if (tcpcc_entry_append(arguments, &count, capacity, "--forward=%s=%s",
				       config->forwards[index].listen,
				       config->forwards[index].backend))
			goto allocation_error;
	}
	if ((config->kernel && tcpcc_entry_append(arguments, &count, capacity,
						  "--kernel=%s", config->kernel)) ||
	    (config->has_memory_mib && tcpcc_entry_append(arguments, &count, capacity,
							  "--memory-mib=%lu", config->memory_mib)) ||
	    (config->firewall_backend && tcpcc_entry_append(arguments, &count, capacity,
							    "--firewall-backend=%s",
							    config->firewall_backend)) ||
	    (config->iptables_variant && tcpcc_entry_append(arguments, &count, capacity,
							    "--iptables-variant=%s",
							    config->iptables_variant)) ||
	    (config->tun_name && tcpcc_entry_append(arguments, &count, capacity,
						    "--tun-name=%s", config->tun_name)) ||
	    (config->tun_host_address && tcpcc_entry_append(arguments, &count, capacity,
							    "--tun-host-address=%s",
							    config->tun_host_address)) ||
	    (config->tun_guest_address && tcpcc_entry_append(arguments, &count, capacity,
							     "--tun-guest-address=%s",
							     config->tun_guest_address)) ||
	    (config->has_backlog && tcpcc_entry_append(arguments, &count, capacity,
						       "--backlog=%lu", config->backlog)) ||
	    (config->has_max_connections && tcpcc_entry_append(arguments, &count, capacity,
							       "--max-connections=%lu",
							       config->max_connections)) ||
	    (config->has_shutdown_grace_period &&
	     tcpcc_entry_append(arguments, &count, capacity,
				"--shutdown-grace-period=%.17g",
				config->shutdown_grace_period)))
		goto allocation_error;

	*result_argv = arguments;
	*result_argc = count;
	return 0;

allocation_error:
	tcpcc_entry_free_generated(arguments, count);
	return tcpcc_entry_error("allocating configuration arguments failed");
}

static int tcpcc_entry_run_config(const char *argv0, const char *path, bool check)
{
	struct tcpcc_file_config config;
	char error[512];
	char **arguments = NULL;
	int argument_count = 0;
	int result;

	if (tcpcc_config_load(path, &config, error, sizeof(error)))
		return tcpcc_entry_error(error);
	if (config.has_tcp_wmem_max_kib &&
	    tcpcc_entry_set_tcp_wmem(config.tcp_wmem_max_kib)) {
		tcpcc_config_free(&config);
		return 1;
	}
	if (tcpcc_entry_build_config_argv(argv0, &config, check,
					  &arguments, &argument_count)) {
		tcpcc_config_free(&config);
		return 1;
	}
	result = tcpcc_cli_main(argument_count, arguments);
	tcpcc_entry_free_generated(arguments, argument_count);
	tcpcc_config_free(&config);
	return result;
}

static int tcpcc_entry_run_direct(int argc, char **argv)
{
	char **filtered;
	unsigned long value;
	bool tcp_wmem_seen = false;
	int filtered_argc = 1;
	int index;

	filtered = calloc((size_t)argc + 1, sizeof(*filtered));
	if (!filtered)
		return tcpcc_entry_error("allocating argument vector failed");
	filtered[0] = argv[0];

	for (index = 1; index < argc; index++) {
		const char *argument = argv[index];
		const char *value_text = NULL;
		bool consume_next = false;

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
				return tcpcc_entry_memory_error();
			}
		} else if (!strncmp(argument, "--memory-mib=", 13)) {
			value_text = argument + 13;
			if (tcpcc_entry_parse_unsigned(value_text,
						       TCPCC_HOSTED_MINIMUM_MEMORY_MIB,
						       ~0UL, &value)) {
				free(filtered);
				return tcpcc_entry_memory_error();
			}
		}

		if (!strcmp(argument, "--tcp-wmem-max-kib")) {
			if (index + 1 >= argc) {
				free(filtered);
				return tcpcc_entry_error("--tcp-wmem-max-kib requires an argument");
			}
			value_text = argv[index + 1];
			consume_next = true;
		} else if (!strncmp(argument, TCPCC_TCP_WMEM_OPTION,
				   sizeof(TCPCC_TCP_WMEM_OPTION) - 1)) {
			value_text = argument + sizeof(TCPCC_TCP_WMEM_OPTION) - 1;
		}
		if (value_text &&
		    (!strcmp(argument, "--tcp-wmem-max-kib") ||
		     !strncmp(argument, TCPCC_TCP_WMEM_OPTION,
			      sizeof(TCPCC_TCP_WMEM_OPTION) - 1))) {
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
			if (tcpcc_entry_set_tcp_wmem(value)) {
				free(filtered);
				return 1;
			}
			tcp_wmem_seen = true;
			if (consume_next)
				index++;
			continue;
		}

		filtered[filtered_argc++] = argv[index];
	}
	filtered[filtered_argc] = NULL;
	index = tcpcc_cli_main(filtered_argc, filtered);
	free(filtered);
	return index;
}

int main(int argc, char **argv)
{
	const char *config_path;
	bool help;
	bool check = false;
	int index;

	/*
	 * Runtime status is commonly piped through tee/logger. If that consumer
	 * exits together with the initiating terminal, teardown must still reach
	 * the owned firewall and TUN rollback rather than dying on the first
	 * shutdown log write with SIGPIPE. stdio will instead observe EPIPE while
	 * the supervisor continues through its cleanup path.
	 */
	if (tcpcc_entry_ignore_sigpipe())
		return tcpcc_entry_error("ignoring SIGPIPE failed");
	if (unsetenv(TCPCC_TCP_WMEM_MAX_KIB_ENV) != 0)
		return tcpcc_entry_error("clearing internal tcp_wmem launch state failed");
	if (tcpcc_entry_find_config(argc, argv, &config_path, &help))
		return 1;
	if (help) {
		tcpcc_entry_usage(stdout);
		return 0;
	}
	if (!config_path)
		return tcpcc_entry_run_direct(argc, argv);
	if (tcpcc_entry_validate_config_argv(argc, argv))
		return 1;
	for (index = 1; index < argc; index++)
		if (!strcmp(argv[index], "--check"))
			check = true;
	return tcpcc_entry_run_config(argv[0], config_path, check);
}

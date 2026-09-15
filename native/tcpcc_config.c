// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_config.h"
#include "third_party/toml-c.h"

/* toml-c's single-header implementation intentionally poisons these names. */
#undef calloc
#undef strdup
#undef strndup

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define TCPCC_CONFIG_VERSION 1UL
#define TCPCC_CONFIG_MAX_BYTES (1024U * 1024U)

static int tcpcc_config_error(char *error, size_t error_size,
			      const char *format, ...)
{
	va_list arguments;

	if (error && error_size) {
		va_start(arguments, format);
		vsnprintf(error, error_size, format, arguments);
		va_end(arguments);
	}
	return -1;
}

static bool tcpcc_table_has_key(const toml_table_t *table, const char *name)
{
	int count = toml_table_len(table);
	int index;

	for (index = 0; index < count; index++) {
		int key_length = 0;
		const char *key = toml_table_key(table, index, &key_length);

		if (key && key_length == (int)strlen(name) &&
		    !memcmp(key, name, (size_t)key_length))
			return true;
	}
	return false;
}

static bool tcpcc_root_key_known(const char *key)
{
	static const char *const keys[] = {
		"version",
		"cc",
		"kernel",
		"memory_mib",
		"tcp_wmem_max_kib",
		"firewall_backend",
		"iptables_variant",
		"tun_name",
		"tun_host_address",
		"tun_guest_address",
		"backlog",
		"max_connections",
		"shutdown_grace_period",
		"forward",
	};
	size_t index;

	for (index = 0; index < sizeof(keys) / sizeof(keys[0]); index++)
		if (!strcmp(key, keys[index]))
			return true;
	return false;
}

static int tcpcc_check_root_keys(const toml_table_t *root,
				 char *error, size_t error_size)
{
	int count = toml_table_len(root);
	int index;

	for (index = 0; index < count; index++) {
		int key_length = 0;
		const char *key = toml_table_key(root, index, &key_length);
		char name[128];

		if (!key || key_length <= 0 || key_length >= (int)sizeof(name))
			return tcpcc_config_error(error, error_size,
				"configuration contains an unsupported top-level key");
		memcpy(name, key, (size_t)key_length);
		name[key_length] = '\0';
		if (!tcpcc_root_key_known(name))
			return tcpcc_config_error(error, error_size,
				"unknown configuration key '%s'", name);
	}
	return 0;
}

static int tcpcc_check_forward_keys(const toml_table_t *table, size_t route,
				    char *error, size_t error_size)
{
	int count = toml_table_len(table);
	int index;

	for (index = 0; index < count; index++) {
		int key_length = 0;
		const char *key = toml_table_key(table, index, &key_length);
		char name[128];

		if (!key || key_length <= 0 || key_length >= (int)sizeof(name))
			return tcpcc_config_error(error, error_size,
				"forward[%zu] contains an unsupported key", route);
		memcpy(name, key, (size_t)key_length);
		name[key_length] = '\0';
		if (strcmp(name, "listen") && strcmp(name, "backend"))
			return tcpcc_config_error(error, error_size,
				"unknown forward[%zu] key '%s'", route, name);
	}
	return 0;
}

static int tcpcc_toml_string(const toml_table_t *table, const char *key,
			     bool required, char **result,
			     char *error, size_t error_size)
{
	toml_value_t value;

	if (!tcpcc_table_has_key(table, key)) {
		if (required)
			return tcpcc_config_error(error, error_size,
				"missing required configuration key '%s'", key);
		return 0;
	}
	value = toml_table_string(table, key);
	if (!value.ok)
		return tcpcc_config_error(error, error_size,
			"configuration key '%s' must be a string", key);
	if (value.u.sl < 0 || strlen(value.u.s) != (size_t)value.u.sl) {
		free(value.u.s);
		return tcpcc_config_error(error, error_size,
			"configuration key '%s' must not contain NUL bytes", key);
	}
	*result = value.u.s;
	return 0;
}

static int tcpcc_toml_unsigned(const toml_table_t *table, const char *key,
			       bool required, unsigned long *result,
			       bool *present, char *error, size_t error_size)
{
	toml_value_t value;

	if (!tcpcc_table_has_key(table, key)) {
		if (required)
			return tcpcc_config_error(error, error_size,
				"missing required configuration key '%s'", key);
		if (present)
			*present = false;
		return 0;
	}
	value = toml_table_int(table, key);
	if (!value.ok || value.u.i < 0 || (uint64_t)value.u.i > (uint64_t)ULONG_MAX)
		return tcpcc_config_error(error, error_size,
			"configuration key '%s' must be a non-negative integer", key);
	*result = (unsigned long)value.u.i;
	if (present)
		*present = true;
	return 0;
}

static int tcpcc_toml_double(const toml_table_t *table, const char *key,
			     double *result, bool *present,
			     char *error, size_t error_size)
{
	toml_value_t value;

	if (!tcpcc_table_has_key(table, key)) {
		*present = false;
		return 0;
	}
	value = toml_table_double(table, key);
	if (!value.ok || !isfinite(value.u.d))
		return tcpcc_config_error(error, error_size,
			"configuration key '%s' must be a finite number", key);
	*result = value.u.d;
	*present = true;
	return 0;
}

static int tcpcc_parse_forwards(const toml_table_t *root,
				struct tcpcc_file_config *config,
				char *error, size_t error_size)
{
	toml_array_t *array;
	int count;
	int index;

	if (!tcpcc_table_has_key(root, "forward"))
		return tcpcc_config_error(error, error_size,
			"missing required configuration key 'forward'");
	array = toml_table_array(root, "forward");
	if (!array || array->kind != 't')
		return tcpcc_config_error(error, error_size,
			"configuration key 'forward' must use [[forward]] tables");
	count = toml_array_len(array);
	if (count <= 0)
		return tcpcc_config_error(error, error_size,
			"configuration must contain at least one [[forward]] table");
	config->forwards = calloc((size_t)count, sizeof(*config->forwards));
	if (!config->forwards)
		return tcpcc_config_error(error, error_size,
			"allocating forward configuration failed");
	config->forward_count = (size_t)count;

	for (index = 0; index < count; index++) {
		toml_table_t *table = toml_array_table(array, index);
		struct tcpcc_file_forward *forward = &config->forwards[index];

		if (!table)
			return tcpcc_config_error(error, error_size,
				"forward[%d] must be a table", index);
		if (tcpcc_check_forward_keys(table, (size_t)index, error, error_size) ||
		    tcpcc_toml_string(table, "listen", true, &forward->listen,
				      error, error_size) ||
		    tcpcc_toml_string(table, "backend", true, &forward->backend,
				      error, error_size))
			return -1;
	}
	return 0;
}

void tcpcc_config_free(struct tcpcc_file_config *config)
{
	size_t index;

	if (!config)
		return;
	free(config->cc);
	free(config->kernel);
	free(config->firewall_backend);
	free(config->iptables_variant);
	free(config->tun_name);
	free(config->tun_host_address);
	free(config->tun_guest_address);
	for (index = 0; index < config->forward_count; index++) {
		free(config->forwards[index].listen);
		free(config->forwards[index].backend);
	}
	free(config->forwards);
	memset(config, 0, sizeof(*config));
}

int tcpcc_config_load(const char *path, struct tcpcc_file_config *config,
		      char *error, size_t error_size)
{
	FILE *stream = NULL;
	struct stat status;
	toml_table_t *root = NULL;
	unsigned long version = 0;
	char toml_error[256];
	int result = -1;

	if (!path || !path[0] || !config)
		return tcpcc_config_error(error, error_size,
			"configuration path is invalid");
	memset(config, 0, sizeof(*config));
	if (error && error_size)
		error[0] = '\0';

	stream = fopen(path, "r");
	if (!stream)
		return tcpcc_config_error(error, error_size,
			"opening configuration '%s' failed: %s", path, strerror(errno));
	if (fstat(fileno(stream), &status) != 0) {
		tcpcc_config_error(error, error_size,
			"stat of configuration '%s' failed: %s", path, strerror(errno));
		goto out;
	}
	if (status.st_size > (off_t)TCPCC_CONFIG_MAX_BYTES) {
		tcpcc_config_error(error, error_size,
			"configuration '%s' exceeds the 1 MiB limit", path);
		goto out;
	}
	root = toml_parse_file(stream, toml_error, sizeof(toml_error));
	if (!root) {
		tcpcc_config_error(error, error_size,
			"invalid TOML in '%s': %s", path,
			toml_error[0] ? toml_error : "parse failed");
		goto out;
	}
	if (tcpcc_check_root_keys(root, error, error_size) ||
	    tcpcc_toml_unsigned(root, "version", true, &version, NULL,
				 error, error_size))
		goto out;
	if (version != TCPCC_CONFIG_VERSION) {
		tcpcc_config_error(error, error_size,
			"unsupported configuration version %lu (expected %lu)",
			version, TCPCC_CONFIG_VERSION);
		goto out;
	}
	if (tcpcc_toml_string(root, "cc", true, &config->cc, error, error_size) ||
	    tcpcc_toml_string(root, "kernel", false, &config->kernel, error, error_size) ||
	    tcpcc_toml_string(root, "firewall_backend", false,
			      &config->firewall_backend, error, error_size) ||
	    tcpcc_toml_string(root, "iptables_variant", false,
			      &config->iptables_variant, error, error_size) ||
	    tcpcc_toml_string(root, "tun_name", false, &config->tun_name,
			      error, error_size) ||
	    tcpcc_toml_string(root, "tun_host_address", false,
			      &config->tun_host_address, error, error_size) ||
	    tcpcc_toml_string(root, "tun_guest_address", false,
			      &config->tun_guest_address, error, error_size) ||
	    tcpcc_toml_unsigned(root, "memory_mib", false, &config->memory_mib,
				&config->has_memory_mib, error, error_size) ||
	    tcpcc_toml_unsigned(root, "tcp_wmem_max_kib", false,
				&config->tcp_wmem_max_kib,
				&config->has_tcp_wmem_max_kib, error, error_size) ||
	    tcpcc_toml_unsigned(root, "backlog", false, &config->backlog,
				&config->has_backlog, error, error_size) ||
	    tcpcc_toml_unsigned(root, "max_connections", false,
				&config->max_connections,
				&config->has_max_connections, error, error_size) ||
	    tcpcc_toml_double(root, "shutdown_grace_period",
			      &config->shutdown_grace_period,
			      &config->has_shutdown_grace_period,
			      error, error_size) ||
	    tcpcc_parse_forwards(root, config, error, error_size))
		goto out;
	result = 0;
out:
	if (root)
		toml_free(root);
	fclose(stream);
	if (result)
		tcpcc_config_free(config);
	return result;
}

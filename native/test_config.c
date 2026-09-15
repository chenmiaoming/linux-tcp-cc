// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void fail(const char *message)
{
	fprintf(stderr, "test-config: %s\n", message);
	exit(1);
}

static void expect(bool condition, const char *message)
{
	if (!condition)
		fail(message);
}

static void write_all(int fd, const char *text)
{
	size_t left = strlen(text);
	const char *cursor = text;

	while (left) {
		ssize_t written = write(fd, cursor, left);

		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0)
			fail("writing temporary config failed");
		cursor += written;
		left -= (size_t)written;
	}
}

static void expect_invalid(const char *text, const char *needle)
{
	char path[] = "/tmp/tcpcc-config-XXXXXX";
	struct tcpcc_file_config config;
	char error[512];
	int fd = mkstemp(path);
	int result;

	if (fd < 0)
		fail("creating temporary config failed");
	write_all(fd, text);
	if (close(fd) != 0)
		fail("closing temporary config failed");
	result = tcpcc_config_load(path, &config, error, sizeof(error));
	unlink(path);
	if (!result) {
		tcpcc_config_free(&config);
		fail("invalid config was accepted");
	}
	if (!strstr(error, needle)) {
		fprintf(stderr, "test-config: expected error containing '%s', got '%s'\n",
			needle, error);
		exit(1);
	}
}

int main(int argc, char **argv)
{
	struct tcpcc_file_config config;
	char error[512];

	if (argc != 2)
		fail("usage: test-config EXAMPLE.toml");
	if (tcpcc_config_load(argv[1], &config, error, sizeof(error))) {
		fprintf(stderr, "test-config: loading example failed: %s\n", error);
		return 1;
	}
	expect(config.cc && !strcmp(config.cc, "bbr"), "example cc mismatch");
	expect(config.has_memory_mib && config.memory_mib == 128,
	       "example memory_mib mismatch");
	expect(config.firewall_backend && !strcmp(config.firewall_backend, "nft-lib"),
	       "example firewall backend mismatch");
	expect(config.forward_count == 2, "example forward count mismatch");
	expect(!strcmp(config.forwards[0].listen, "203.0.113.10:443"),
	       "example first listener mismatch");
	expect(!strcmp(config.forwards[0].backend, "127.0.0.1:8443"),
	       "example first backend mismatch");
	expect(!strcmp(config.forwards[1].listen, "203.0.113.10:8443"),
	       "example second listener mismatch");
	expect(!strcmp(config.forwards[1].backend, "127.0.0.1:9443"),
	       "example second backend mismatch");
	expect(!config.has_tcp_wmem_max_kib,
	       "commented tcp_wmem setting unexpectedly became present");
	tcpcc_config_free(&config);

	expect_invalid(
		"version = 1\ncc = \"bbr\"\nunknown = true\n"
		"[[forward]]\nlisten = \"203.0.113.10:443\"\n"
		"backend = \"127.0.0.1:8443\"\n",
		"unknown configuration key 'unknown'");
	expect_invalid(
		"version = 2\ncc = \"bbr\"\n"
		"[[forward]]\nlisten = \"203.0.113.10:443\"\n"
		"backend = \"127.0.0.1:8443\"\n",
		"unsupported configuration version 2");
	expect_invalid(
		"version = 1\ncc = \"bbr\"\n"
		"[[forward]]\nlisten = \"203.0.113.10:443\"\n"
		"backend = \"127.0.0.1:8443\"\nextra = 1\n",
		"unknown forward[0] key 'extra'");
	expect_invalid(
		"version = 1\nversion = 1\ncc = \"bbr\"\n"
		"[[forward]]\nlisten = \"203.0.113.10:443\"\n"
		"backend = \"127.0.0.1:8443\"\n",
		"key already defined");

	return 0;
}

// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_control.h"
#include "tcpcc_event.h"
#include "tcpcc_process.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TCPCC_EVENT_SCHEMA "tcpcc.runtime.v1"
#define TCPCC_DEFAULT_BACKLOG 128U
#define TCPCC_DEFAULT_ACCEPT_BATCH 64U
#define TCPCC_MAX_BACKLOG 4096U
#define TCPCC_MAX_CONNECTIONS 1048575U
#define TCPCC_DEFAULT_GRACE_MS 5000U
#define TCPCC_MAX_GRACE_MS 300000U
#define TCPCC_CONTROL_TIMEOUT_MS 30000
#define TCPCC_TUN_MTU "1500"
#define TCPCC_SIGNAL_TOKEN 1U
#define TCPCC_CHILD_TOKEN 2U

enum tcpcc_firewall_kind {
	TCPCC_FIREWALL_NFT_LIB,
	TCPCC_FIREWALL_NFT_EXEC,
	TCPCC_FIREWALL_IPTABLES,
};

struct tcpcc_endpoint {
	int version;
	char address[INET6_ADDRSTRLEN];
	unsigned char packed[16];
	uint16_t port;
};

struct tcpcc_cli_config {
	struct tcpcc_endpoint listen;
	struct tcpcc_endpoint backend;
	char cc[16];
	char kernel[4096];
	unsigned long memory_mib;
	enum tcpcc_firewall_kind firewall;
	char firewall_name[16];
	char iptables_variant[32];
	char tun_name[IFNAMSIZ];
	char tun_host[INET6_ADDRSTRLEN];
	char tun_guest[INET6_ADDRSTRLEN];
	unsigned int backlog;
	unsigned int max_connections;
	unsigned int grace_ms;
};

struct tcpcc_firewall {
	enum tcpcc_firewall_kind kind;
	int version;
	char resource[33];
	char command[40];
	char restore_command[48];
	char listen[INET6_ADDRSTRLEN];
	char guest[INET6_ADDRSTRLEN];
	char tun_name[IFNAMSIZ];
	uint16_t port;
	unsigned long long owner_start;
	bool installed;
};

struct tcpcc_nft_api {
	void *library;
	void *(*ctx_new)(uint32_t);
	void (*ctx_free)(void *);
	void (*buffer_output)(void *);
	void (*buffer_error)(void *);
	const char *(*get_output_buffer)(void *);
	const char *(*get_error_buffer)(void *);
	void (*set_dry_run)(void *, bool);
	int (*run_buffer)(void *, const char *);
};

static int tcpcc_nft_load(struct tcpcc_nft_api *api);

static void tcpcc_usage(FILE *stream)
{
	fprintf(stream,
		"usage: tcpcc --listen IP:PORT --backend 127.0.0.1:PORT --cc NAME [options]\n"
		"\n"
		"Terminate public TCP inside the hosted Linux stack and bridge it to\n"
		"one local backend. The installed command has no Python dependency.\n"
		"\n"
		"  --kernel PATH                 hosted vmlinux (or TCPCC_KERNEL)\n"
		"  --memory-mib MIB              hosted memory, minimum 128 (default 128)\n"
		"  --firewall-backend NAME       nft-lib, nft-exec, or iptables\n"
		"  --iptables-variant NAME       iptables, iptables-nft, or iptables-legacy\n"
		"  --tun-name NAME               exclusive nonpersistent TUN name\n"
		"  --tun-host-address IP         host-side point-to-point address\n"
		"  --tun-guest-address IP        hosted point-to-point address\n"
		"  --backlog N                   listener backlog (default 128)\n"
		"  --max-connections N           0 means no policy limit (default 0)\n"
		"  --shutdown-grace-period SEC   graceful drain timeout (default 5)\n");
}

static int tcpcc_error(const char *message)
{
	fprintf(stderr, "tcpcc: error: %s\n", message);
	return -1;
}

static int tcpcc_errno(const char *what)
{
	fprintf(stderr, "tcpcc: error: %s: %s\n", what, strerror(errno));
	return -1;
}

static bool tcpcc_valid_name(const char *value, size_t maximum, bool cc)
{
	size_t index;
	size_t length = strlen(value);

	if (!length || length > maximum)
		return false;
	for (index = 0; index < length; index++) {
		unsigned char byte = (unsigned char)value[index];

		if ((byte >= 'a' && byte <= 'z') ||
		    (byte >= '0' && byte <= '9') || byte == '_' || byte == '-')
			continue;
		if (!cc && ((byte >= 'A' && byte <= 'Z') || byte == '.'))
			continue;
		return false;
	}
	return strcmp(value, ".") && strcmp(value, "..");
}

static int tcpcc_parse_unsigned(const char *text, unsigned long maximum,
				unsigned long *result)
{
	char *end = NULL;
	unsigned long value;

	if (!text[0] || text[0] < '0' || text[0] > '9')
		return -1;
	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno || !end || *end || value > maximum)
		return -1;
	*result = value;
	return 0;
}

static int tcpcc_parse_endpoint(const char *text, struct tcpcc_endpoint *endpoint)
{
	char address[INET6_ADDRSTRLEN];
	const char *port_text;
	size_t length;
	unsigned long port;
	int version;

	memset(endpoint, 0, sizeof(*endpoint));
	if (text[0] == '[') {
		const char *closing = strchr(text, ']');

		if (!closing || closing[1] != ':' || !closing[2])
			return -1;
		length = (size_t)(closing - text - 1);
		if (!length || length >= sizeof(address))
			return -1;
		memcpy(address, text + 1, length);
		address[length] = '\0';
		port_text = closing + 2;
		version = 6;
	} else {
		const char *colon = strrchr(text, ':');

		if (!colon || strchr(text, ':') != colon)
			return -1;
		length = (size_t)(colon - text);
		if (!length || length >= sizeof(address))
			return -1;
		memcpy(address, text, length);
		address[length] = '\0';
		port_text = colon + 1;
		version = 4;
	}
	if (tcpcc_parse_unsigned(port_text, 65535, &port) || !port)
		return -1;
	if (inet_pton(version == 4 ? AF_INET : AF_INET6, address,
		      endpoint->packed) != 1)
		return -1;
	if (!memcmp(endpoint->packed, version == 4 ? "\0\0\0\0" :
		    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
		    version == 4 ? 4U : 16U))
		return -1;
	endpoint->version = version;
	endpoint->port = (uint16_t)port;
	if (!inet_ntop(version == 4 ? AF_INET : AF_INET6, endpoint->packed,
		       endpoint->address, sizeof(endpoint->address)))
		return -1;
	return 0;
}

static int tcpcc_parse_ip(const char *text, int version, char *canonical)
{
	unsigned char packed[16];
	int family = version == 4 ? AF_INET : AF_INET6;

	if (inet_pton(family, text, packed) != 1 ||
	    !inet_ntop(family, packed, canonical, INET6_ADDRSTRLEN))
		return -1;
	return 0;
}

static int tcpcc_default_kernel(char *buffer, size_t size, const char *argv0)
{
	const char *environment = getenv("TCPCC_KERNEL");
	char executable[4096];
	ssize_t length;
	char *slash;

	if (environment && environment[0]) {
		if (snprintf(buffer, size, "%s", environment) >= (int)size)
			return -1;
		return 0;
	}
	if (access(".build/tcpcc-bootstrap-out/vmlinux", X_OK) == 0) {
		snprintf(buffer, size, "%s", ".build/tcpcc-bootstrap-out/vmlinux");
		return 0;
	}
	length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
	if (length < 0) {
		if (!argv0 || !strchr(argv0, '/'))
			return -1;
		if (snprintf(executable, sizeof(executable), "%s", argv0) >=
		    (int)sizeof(executable))
			return -1;
	} else {
		executable[length] = '\0';
	}
	slash = strrchr(executable, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	if (snprintf(buffer, size, "%s/../libexec/tcpcc/vmlinux", executable) >=
	    (int)size)
		return -1;
	return 0;
}

static int tcpcc_parse_args(int argc, char **argv, struct tcpcc_cli_config *config)
{
	static const struct option options[] = {
		{ "listen", required_argument, NULL, 'l' },
		{ "backend", required_argument, NULL, 'b' },
		{ "cc", required_argument, NULL, 'c' },
		{ "kernel", required_argument, NULL, 'k' },
		{ "memory-mib", required_argument, NULL, 'm' },
		{ "firewall-backend", required_argument, NULL, 'f' },
		{ "iptables-variant", required_argument, NULL, 'i' },
		{ "tun-name", required_argument, NULL, 't' },
		{ "tun-host-address", required_argument, NULL, 1000 },
		{ "tun-guest-address", required_argument, NULL, 1001 },
		{ "backlog", required_argument, NULL, 1002 },
		{ "max-connections", required_argument, NULL, 1003 },
		{ "shutdown-grace-period", required_argument, NULL, 1004 },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	const char *listen = NULL;
	const char *backend = NULL;
	const char *cc = NULL;
	const char *host = NULL;
	const char *guest = NULL;
	bool explicit_iptables = false;
	int option;

	memset(config, 0, sizeof(*config));
	config->memory_mib = TCPCC_HOSTED_DEFAULT_MEMORY_MIB;
	config->firewall = TCPCC_FIREWALL_NFT_LIB;
	strcpy(config->firewall_name, "nft-lib");
	strcpy(config->iptables_variant, "iptables");
	config->backlog = TCPCC_DEFAULT_BACKLOG;
	config->grace_ms = TCPCC_DEFAULT_GRACE_MS;
	if (tcpcc_default_kernel(config->kernel, sizeof(config->kernel), argv[0]))
		return tcpcc_error("cannot resolve the default hosted kernel path");

	while ((option = getopt_long(argc, argv, "l:b:c:k:m:f:i:t:h", options,
				     NULL)) != -1) {
		unsigned long value;
		char *end;
		double seconds;

		switch (option) {
		case 'l': listen = optarg; break;
		case 'b': backend = optarg; break;
		case 'c': cc = optarg; break;
		case 'k':
			if (snprintf(config->kernel, sizeof(config->kernel), "%s", optarg) >=
			    (int)sizeof(config->kernel))
				return tcpcc_error("kernel path is too long");
			break;
		case 'm':
			if (tcpcc_parse_unsigned(optarg, ~0UL, &value) ||
			    value < TCPCC_HOSTED_MINIMUM_MEMORY_MIB)
				return tcpcc_error("hosted memory must be at least 128 MiB");
			config->memory_mib = value;
			break;
		case 'f':
			if (!strcmp(optarg, "nft-lib"))
				config->firewall = TCPCC_FIREWALL_NFT_LIB;
			else if (!strcmp(optarg, "nft-exec"))
				config->firewall = TCPCC_FIREWALL_NFT_EXEC;
			else if (!strcmp(optarg, "iptables"))
				config->firewall = TCPCC_FIREWALL_IPTABLES;
			else
				return tcpcc_error("firewall backend must be nft-lib, nft-exec, or iptables");
			strcpy(config->firewall_name, optarg);
			break;
		case 'i':
			if (strcmp(optarg, "iptables") && strcmp(optarg, "iptables-nft") &&
			    strcmp(optarg, "iptables-legacy"))
				return tcpcc_error("invalid iptables variant");
			strcpy(config->iptables_variant, optarg);
			explicit_iptables = true;
			break;
		case 't':
			if (!tcpcc_valid_name(optarg, IFNAMSIZ - 1, false))
				return tcpcc_error("invalid TUN name");
			strcpy(config->tun_name, optarg);
			break;
		case 1000: host = optarg; break;
		case 1001: guest = optarg; break;
		case 1002:
			if (tcpcc_parse_unsigned(optarg, TCPCC_MAX_BACKLOG, &value) || !value)
				return tcpcc_error("backlog must be from 1 through 4096");
			config->backlog = (unsigned int)value;
			break;
		case 1003:
			if (tcpcc_parse_unsigned(optarg, TCPCC_MAX_CONNECTIONS, &value))
				return tcpcc_error("max connections must be 0 or at most 1048575");
			config->max_connections = (unsigned int)value;
			break;
		case 1004:
			errno = 0;
			seconds = strtod(optarg, &end);
			if (errno || !optarg[0] || *end || seconds != seconds ||
			    seconds < 0 || seconds > 300)
				return tcpcc_error("shutdown grace period must be from 0 through 300 seconds");
			config->grace_ms = (unsigned int)(seconds * 1000.0);
			break;
		case 'h': tcpcc_usage(stdout); exit(0);
		default: tcpcc_usage(stderr); return -1;
		}
	}
	if (optind != argc || !listen || !backend || !cc)
		return tcpcc_error("--listen, --backend, and --cc are required");
	if (tcpcc_parse_endpoint(listen, &config->listen))
		return tcpcc_error("listen must use literal IPv4:port or [IPv6]:port syntax");
	if (tcpcc_parse_endpoint(backend, &config->backend) ||
	    config->backend.version != 4 || strcmp(config->backend.address, "127.0.0.1"))
		return tcpcc_error("backend must use 127.0.0.1:port");
	if (!tcpcc_valid_name(cc, 15, true))
		return tcpcc_error("cc must contain 1-15 lowercase letters, digits, underscores, or hyphens");
	strcpy(config->cc, cc);
	if (explicit_iptables && config->firewall != TCPCC_FIREWALL_IPTABLES)
		return tcpcc_error("--iptables-variant is valid only with --firewall-backend=iptables");
	if (!host)
		host = config->listen.version == 4 ? "198.18.0.1" : "fd00:198:18::1";
	if (!guest)
		guest = config->listen.version == 4 ? "198.18.0.2" : "fd00:198:18::2";
	if (tcpcc_parse_ip(host, config->listen.version, config->tun_host) ||
	    tcpcc_parse_ip(guest, config->listen.version, config->tun_guest) ||
	    !strcmp(config->tun_host, config->tun_guest))
		return tcpcc_error("TUN addresses must be distinct usable addresses matching the listener family");
	return 0;
}

static int tcpcc_run(char *const argv[], const char *input, bool quiet)
{
	int pipefd[2] = { -1, -1 };
	pid_t child;
	int status;

	if (input && pipe2(pipefd, O_CLOEXEC))
		return -1;
	child = fork();
	if (child < 0)
		goto fail;
	if (!child) {
		if (input && dup2(pipefd[0], STDIN_FILENO) < 0)
			_exit(126);
		if (quiet) {
			int nullfd = open("/dev/null", O_WRONLY);

			if (nullfd >= 0) {
				dup2(nullfd, STDOUT_FILENO);
				dup2(nullfd, STDERR_FILENO);
			}
		}
		if (input) {
			close(pipefd[0]);
			close(pipefd[1]);
		}
		execvp(argv[0], argv);
		_exit(errno == ENOENT ? 127 : 126);
	}
	if (input) {
		const char *cursor = input;
		size_t remaining = strlen(input);

		close(pipefd[0]);
		pipefd[0] = -1;
		while (remaining) {
			ssize_t written = write(pipefd[1], cursor, remaining);

			if (written < 0 && errno == EINTR)
				continue;
			if (written <= 0)
				break;
			cursor += written;
			remaining -= (size_t)written;
		}
		close(pipefd[1]);
		pipefd[1] = -1;
	}
	while (waitpid(child, &status, 0) < 0) {
		if (errno != EINTR)
			return -1;
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
fail:
	if (pipefd[0] >= 0) close(pipefd[0]);
	if (pipefd[1] >= 0) close(pipefd[1]);
	return -1;
}

static int tcpcc_capture(char *const argv[], char *output, size_t capacity)
{
	int pipefd[2];
	pid_t child;
	size_t used = 0;
	int status;

	if (!output || capacity < 2 || pipe2(pipefd, O_CLOEXEC))
		return -1;
	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}
	if (!child) {
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(126);
		close(pipefd[0]);
		close(pipefd[1]);
		execvp(argv[0], argv);
		_exit(errno == ENOENT ? 127 : 126);
	}
	close(pipefd[1]);
	for (;;) {
		ssize_t count = read(pipefd[0], output + used, capacity - used - 1);

		if (count < 0 && errno == EINTR)
			continue;
		if (count < 0) {
			close(pipefd[0]);
			return -1;
		}
		if (!count)
			break;
		used += (size_t)count;
		if (used == capacity - 1) {
			close(pipefd[0]);
			kill(child, SIGKILL);
			while (waitpid(child, &status, 0) < 0 && errno == EINTR)
				;
			return -1;
		}
	}
	close(pipefd[0]);
	output[used] = '\0';
	while (waitpid(child, &status, 0) < 0) {
		if (errno != EINTR)
			return -1;
	}
	return WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : -1;
}

static int tcpcc_read_file(const char *path, char *buffer, size_t size)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t count;

	if (fd < 0)
		return -1;
	count = read(fd, buffer, size - 1);
	close(fd);
	if (count < 0)
		return -1;
	buffer[count] = '\0';
	while (count > 0 && (buffer[count - 1] == '\n' || buffer[count - 1] == '\r'))
		buffer[--count] = '\0';
	return 0;
}

static int tcpcc_process_start_time(pid_t pid, unsigned long long *start_time)
{
	char path[64];
	char stat_line[4096];
	char *cursor;
	unsigned int field;

	snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	if (tcpcc_read_file(path, stat_line, sizeof(stat_line)))
		return -1;
	cursor = strrchr(stat_line, ')');
	if (!cursor)
		return -1;
	cursor++;
	/* cursor begins at field 3; starttime is field 22. */
	for (field = 3; field <= 22; field++) {
		char *end;

		while (*cursor == ' ') cursor++;
		if (!*cursor)
			return -1;
		end = cursor + strcspn(cursor, " ");
		if (field == 22) {
			char saved = *end;
			char *number_end;

			*end = '\0';
			errno = 0;
			*start_time = strtoull(cursor, &number_end, 10);
			*end = saved;
			return errno || number_end != end || !*start_time ? -1 : 0;
		}
		cursor = end;
	}
	return -1;
}

static int tcpcc_check_ownership_text(const char *text)
{
	const char *cursor = text;
	const char prefix[] = "tcpcc.owner.v1";

	while ((cursor = strstr(cursor, prefix)) != NULL) {
		long pid;
		unsigned long long expected;
		unsigned long long actual;
		char tun_name[IFNAMSIZ];
		int consumed = 0;

		if (sscanf(cursor,
			   "tcpcc.owner.v1 pid=%ld start=%llu tun=%15[A-Za-z0-9_.-]%n",
			   &pid, &expected, tun_name, &consumed) != 3 || pid < 1 ||
		    expected < 1 || consumed < 1 ||
		    !tcpcc_valid_name(tun_name, IFNAMSIZ - 1, false)) {
			return tcpcc_error("malformed tcpcc firewall ownership marker blocks startup");
		}
		if (tcpcc_process_start_time((pid_t)pid, &actual) || actual != expected)
			return tcpcc_error("stale tcpcc firewall resource blocks startup; inspect and remove it explicitly");
		cursor += consumed;
	}
	return 0;
}

static bool tcpcc_word_present(const char *words, const char *wanted)
{
	size_t wanted_length = strlen(wanted);
	const char *cursor = words;

	while (*cursor) {
		while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n') cursor++;
		if (!strncmp(cursor, wanted, wanted_length) &&
		    (cursor[wanted_length] == '\0' || cursor[wanted_length] == ' ' ||
		     cursor[wanted_length] == '\t' || cursor[wanted_length] == '\n'))
			return true;
		cursor += strcspn(cursor, " \t\n");
	}
	return false;
}

static bool tcpcc_executable_on_path(const char *name)
{
	const char *path = getenv("PATH");
	char *copy;
	char *cursor;
	char *save = NULL;
	bool found = false;

	if (strchr(name, '/'))
		return access(name, X_OK) == 0;
	if (!path)
		return false;
	copy = strdup(path);
	if (!copy)
		return false;
	for (cursor = strtok_r(copy, ":", &save); cursor;
	     cursor = strtok_r(NULL, ":", &save)) {
		char candidate[4096];

		if (snprintf(candidate, sizeof(candidate), "%s/%s",
			     cursor[0] ? cursor : ".", name) < (int)sizeof(candidate) &&
		    access(candidate, X_OK) == 0) {
			found = true;
			break;
		}
	}
	free(copy);
	return found;
}

static bool tcpcc_has_net_admin(void)
{
	char status[8192];
	char *effective;
	unsigned long long mask;

	if (tcpcc_read_file("/proc/self/status", status, sizeof(status)))
		return false;
	effective = strstr(status, "CapEff:");
	if (!effective || sscanf(effective, "CapEff:%llx", &mask) != 1)
		return false;
	return (mask & (1ULL << 12)) != 0;
}

static int tcpcc_validate_kernel(const char *path)
{
	Elf64_Ehdr header;
	Elf64_Phdr program;
	struct stat metadata;
	int fd;
	unsigned int index;

	if (stat(path, &metadata) || !S_ISREG(metadata.st_mode) || access(path, X_OK))
		return tcpcc_error("kernel image is unavailable, non-regular, or not executable");
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return tcpcc_errno("opening kernel image");
	if (read(fd, &header, sizeof(header)) != (ssize_t)sizeof(header) ||
	    memcmp(header.e_ident, ELFMAG, SELFMAG) ||
	    header.e_ident[EI_CLASS] != ELFCLASS64 ||
	    header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_type != ET_EXEC ||
	    header.e_machine != EM_X86_64 || !header.e_entry || !header.e_phnum ||
	    header.e_phentsize < sizeof(program)) {
		close(fd);
		return tcpcc_error("kernel image must be a valid x86-64 little-endian ET_EXEC ELF");
	}
	for (index = 0; index < header.e_phnum; index++) {
		if (pread(fd, &program, sizeof(program),
			  (off_t)header.e_phoff + (off_t)index * header.e_phentsize) !=
		    (ssize_t)sizeof(program)) {
			close(fd);
			return tcpcc_error("kernel image has a truncated program-header table");
		}
		if (program.p_type == PT_INTERP) {
			close(fd);
			return tcpcc_error("kernel image unexpectedly requires an ELF interpreter");
		}
	}
	close(fd);
	return 0;
}

static int tcpcc_iptables_command(const struct tcpcc_cli_config *config,
				  char *command, size_t command_size)
{
	const char *selected = config->iptables_variant;
	size_t length;

	if (config->listen.version == 6) {
		if (!strcmp(config->iptables_variant, "iptables"))
			selected = "ip6tables";
		else if (!strcmp(config->iptables_variant, "iptables-nft"))
			selected = "ip6tables-nft";
		else if (!strcmp(config->iptables_variant, "iptables-legacy"))
			selected = "ip6tables-legacy";
		else
			return -1;
	}
	length = strlen(selected);
	if (length >= command_size)
		return -1;
	memcpy(command, selected, length + 1);
	return 0;
}

static int tcpcc_preflight(const struct tcpcc_cli_config *config)
{
	char value[4096];
	char firewall_command[48];
	const char *forwarding = config->listen.version == 4 ?
		"/proc/sys/net/ipv4/ip_forward" :
		"/proc/sys/net/ipv6/conf/all/forwarding";
	struct stat tun;

	if (!tcpcc_has_net_admin())
		return tcpcc_error("CAP_NET_ADMIN is required");
	if (stat("/dev/net/tun", &tun) || !S_ISCHR(tun.st_mode) ||
	    access("/dev/net/tun", R_OK | W_OK))
		return tcpcc_error("/dev/net/tun must be a readable and writable character device");
	if (tcpcc_read_file(forwarding, value, sizeof(value)) || strcmp(value, "1"))
		return tcpcc_error(config->listen.version == 4 ?
			"net.ipv4.ip_forward must be 1" :
			"net.ipv6.conf.all.forwarding must be 1");
	if (tcpcc_read_file("/proc/sys/net/ipv4/tcp_congestion_control", value,
			    sizeof(value)) || strcmp(value, config->cc))
		return tcpcc_error("host tcp_congestion_control must equal --cc");
	if (tcpcc_read_file("/proc/sys/net/ipv4/tcp_available_congestion_control",
			    value, sizeof(value)) || !tcpcc_word_present(value, config->cc))
		return tcpcc_error("requested congestion control is not available on the host");
	if (!tcpcc_executable_on_path("ip"))
		return tcpcc_error("ip executable is required on PATH");
	if (config->firewall == TCPCC_FIREWALL_NFT_EXEC &&
	    !tcpcc_executable_on_path("nft"))
		return tcpcc_error("nft executable is required on PATH");
	if (config->firewall == TCPCC_FIREWALL_NFT_LIB) {
		struct tcpcc_nft_api api;

		if (tcpcc_nft_load(&api))
			return tcpcc_error("libnftables is required by the selected backend");
		dlclose(api.library);
	}
	if (config->firewall == TCPCC_FIREWALL_IPTABLES) {
		if (tcpcc_iptables_command(config, firewall_command,
					    sizeof(firewall_command)))
			return tcpcc_error("invalid iptables executable selection");
		if (!tcpcc_executable_on_path(firewall_command))
			return tcpcc_error("selected iptables executable is required on PATH");
		snprintf(value, sizeof(value), "%s-save", firewall_command);
		if (!tcpcc_executable_on_path(value))
			return tcpcc_error("selected iptables-save executable is required on PATH");
	}
	return tcpcc_validate_kernel(config->kernel);
}

static int tcpcc_random_hex(char *buffer, size_t bytes)
{
	static const char digits[] = "0123456789abcdef";
	unsigned char random[16];
	size_t index;

	if (bytes > sizeof(random) || getrandom(random, bytes, 0) != (ssize_t)bytes)
		return -1;
	for (index = 0; index < bytes; index++) {
		buffer[index * 2] = digits[random[index] >> 4];
		buffer[index * 2 + 1] = digits[random[index] & 15];
	}
	buffer[bytes * 2] = '\0';
	return 0;
}

static int tcpcc_tun_open(struct tcpcc_cli_config *config)
{
	struct ifreq request = { };
	char host_prefix[INET6_ADDRSTRLEN + 5];
	char guest_prefix[INET6_ADDRSTRLEN + 5];
	char generated[11];
	int fd;
	char *address[] = { "ip", "address", "add", host_prefix, "peer",
		guest_prefix, "dev", config->tun_name, NULL };
	char *link[] = { "ip", "link", "set", "dev", config->tun_name, "mtu",
		TCPCC_TUN_MTU, "up", NULL };
	char *route[] = { "ip", "-6", "route", "replace", guest_prefix, "dev",
		config->tun_name, "src", config->tun_host, NULL };

	if (!config->tun_name[0]) {
		if (tcpcc_random_hex(generated, 5))
			return tcpcc_errno("generating TUN name");
		snprintf(config->tun_name, sizeof(config->tun_name), "tcpcc%s", generated);
	}
	fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return tcpcc_errno("opening /dev/net/tun");
	request.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL;
	snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", config->tun_name);
	if (ioctl(fd, TUNSETIFF, &request)) {
		close(fd);
		return tcpcc_errno("creating exclusive TUN interface");
	}
	snprintf(host_prefix, sizeof(host_prefix), "%s/%u", config->tun_host,
		 config->listen.version == 4 ? 32U : 128U);
	snprintf(guest_prefix, sizeof(guest_prefix), "%s/%u", config->tun_guest,
		 config->listen.version == 4 ? 32U : 128U);
	if (tcpcc_run(address, NULL, false) || tcpcc_run(link, NULL, false) ||
	    (config->listen.version == 6 && tcpcc_run(route, NULL, false))) {
		close(fd);
		return tcpcc_error("configuring point-to-point TUN interface failed");
	}
	return fd;
}

static int tcpcc_nft_load(struct tcpcc_nft_api *api)
{
#define TCPCC_NFT_SYMBOL(member, name) do { \
	*(void **)(&api->member) = dlsym(api->library, name); \
	if (!api->member) goto missing; \
} while (0)
	memset(api, 0, sizeof(*api));
	api->library = dlopen("libnftables.so.1", RTLD_NOW | RTLD_LOCAL);
	if (!api->library)
		api->library = dlopen("libnftables.so", RTLD_NOW | RTLD_LOCAL);
	if (!api->library)
		return -1;
	TCPCC_NFT_SYMBOL(ctx_new, "nft_ctx_new");
	TCPCC_NFT_SYMBOL(ctx_free, "nft_ctx_free");
	TCPCC_NFT_SYMBOL(buffer_output, "nft_ctx_buffer_output");
	TCPCC_NFT_SYMBOL(buffer_error, "nft_ctx_buffer_error");
	TCPCC_NFT_SYMBOL(get_output_buffer, "nft_ctx_get_output_buffer");
	TCPCC_NFT_SYMBOL(get_error_buffer, "nft_ctx_get_error_buffer");
	TCPCC_NFT_SYMBOL(set_dry_run, "nft_ctx_set_dry_run");
	TCPCC_NFT_SYMBOL(run_buffer, "nft_run_cmd_from_buffer");
	return 0;
missing:
	dlclose(api->library);
	memset(api, 0, sizeof(*api));
	return -1;
#undef TCPCC_NFT_SYMBOL
}

static int tcpcc_nft_lib_run(const char *batch, bool dry_run)
{
	struct tcpcc_nft_api api;
	void *context;
	int result;

	if (tcpcc_nft_load(&api))
		return tcpcc_error("libnftables is unavailable or lacks the required API");
	context = api.ctx_new(0);
	if (!context) {
		dlclose(api.library);
		return tcpcc_error("libnftables context allocation failed");
	}
	api.buffer_output(context);
	api.buffer_error(context);
	api.set_dry_run(context, dry_run);
	result = api.run_buffer(context, batch);
	if (result) {
		const char *detail = api.get_error_buffer(context);
		fprintf(stderr, "tcpcc: error: libnftables rejected policy: %s\n",
			detail && detail[0] ? detail : "unknown error");
	}
	api.ctx_free(context);
	dlclose(api.library);
	return result ? -1 : 0;
}

static int tcpcc_nft_lib_capture(const char *command, char *output,
				 size_t capacity)
{
	struct tcpcc_nft_api api;
	const char *captured;
	void *context;
	int result = -1;

	if (tcpcc_nft_load(&api))
		return tcpcc_error("libnftables is unavailable or lacks the required API");
	context = api.ctx_new(0);
	if (!context)
		goto close_library;
	api.buffer_output(context);
	api.buffer_error(context);
	if (api.run_buffer(context, command))
		goto close_context;
	captured = api.get_output_buffer(context);
	if (!captured || strlen(captured) >= capacity)
		goto close_context;
	strcpy(output, captured);
	result = 0;
close_context:
	api.ctx_free(context);
close_library:
	dlclose(api.library);
	return result;
}

static int tcpcc_nft_exec_run(const char *batch, bool dry_run, bool quiet)
{
	char *check[] = { "nft", "--check", "--file", "-", NULL };
	char *apply[] = { "nft", "--file", "-", NULL };

	return tcpcc_run(dry_run ? check : apply, batch, quiet);
}

static int tcpcc_firewall_nft(struct tcpcc_firewall *firewall, bool dry_run)
{
	char batch[2048];
	char destination[INET6_ADDRSTRLEN + 16];
	const char *family = firewall->version == 4 ? "ip" : "ip6";
	const char *selector = family;
	int length;

	if (firewall->version == 6)
		snprintf(destination, sizeof(destination), "[%s]:%u", firewall->guest,
			 firewall->port);
	else
		snprintf(destination, sizeof(destination), "%s:%u", firewall->guest,
			 firewall->port);
	length = snprintf(batch, sizeof(batch),
		"create table %s %s\n"
		"add chain %s %s prerouting { type nat hook prerouting priority dstnat; policy accept; }\n"
		"add rule %s %s prerouting %s daddr %s tcp dport %u counter dnat to %s "
		"comment \"tcpcc.owner.v1 pid=%ld start=%llu tun=%s\"\n",
		family, firewall->resource, family, firewall->resource,
		family, firewall->resource, selector, firewall->listen,
		firewall->port, destination, (long)getpid(), firewall->owner_start,
		firewall->tun_name);
	if (length < 0 || length >= (int)sizeof(batch))
		return tcpcc_error("nftables policy exceeded internal size limit");
	if (firewall->kind == TCPCC_FIREWALL_NFT_LIB)
		return tcpcc_nft_lib_run(batch, dry_run);
	return tcpcc_nft_exec_run(batch, dry_run, false);
}

static int tcpcc_firewall_install_iptables(struct tcpcc_firewall *firewall)
{
	char port[8];
	char prefix[INET6_ADDRSTRLEN + 5];
	char destination[INET6_ADDRSTRLEN + 16];
	char marker[128];
	char *create[] = { firewall->command, "--wait", "-t", "nat", "-N",
		firewall->resource, NULL };
	char *dnat[] = { firewall->command, "--wait", "-t", "nat", "-A",
		firewall->resource, "-d", prefix, "-p", "tcp", "-m", "tcp",
		"--dport", port, "-m", "comment", "--comment", marker, "-j", "DNAT",
		"--to-destination", destination, NULL };
	char *jump[] = { firewall->command, "--wait", "-t", "nat", "-A",
		"PREROUTING", "-d", prefix, "-p", "tcp", "-m", "tcp", "--dport",
		port, "-m", "comment", "--comment", marker, "-j", firewall->resource,
		NULL };

	snprintf(port, sizeof(port), "%u", firewall->port);
	snprintf(prefix, sizeof(prefix), "%s/%u", firewall->listen,
		 firewall->version == 4 ? 32U : 128U);
	if (firewall->version == 6)
		snprintf(destination, sizeof(destination), "[%s]:%u", firewall->guest,
			 firewall->port);
	else
		snprintf(destination, sizeof(destination), "%s:%u", firewall->guest,
			 firewall->port);
	snprintf(marker, sizeof(marker), "tcpcc.owner.v1 pid=%ld start=%llu tun=%s",
		 (long)getpid(), firewall->owner_start, firewall->tun_name);
	if (tcpcc_run(create, NULL, false))
		return -1;
	if (tcpcc_run(dnat, NULL, false) || tcpcc_run(jump, NULL, false)) {
		char *flush[] = { firewall->command, "--wait", "-t", "nat", "-F",
			firewall->resource, NULL };
		char *remove[] = { firewall->command, "--wait", "-t", "nat", "-X",
			firewall->resource, NULL };

		tcpcc_run(flush, NULL, true);
		tcpcc_run(remove, NULL, true);
		return -1;
	}
	return 0;
}

static int tcpcc_firewall_install(const struct tcpcc_cli_config *config,
				  struct tcpcc_firewall *firewall)
{
	char ownership[1024 * 1024];
	char family[4];
	char random[13];

	memset(firewall, 0, sizeof(*firewall));
	if (tcpcc_random_hex(random, 6))
		return tcpcc_errno("generating firewall resource name");
	firewall->kind = config->firewall;
	firewall->version = config->listen.version;
	firewall->port = config->listen.port;
	strcpy(firewall->listen, config->listen.address);
	strcpy(firewall->guest, config->tun_guest);
	strcpy(firewall->tun_name, config->tun_name);
	if (tcpcc_process_start_time(getpid(), &firewall->owner_start))
		return tcpcc_error("cannot read the native supervisor process identity");
	if (config->firewall == TCPCC_FIREWALL_IPTABLES) {
		snprintf(firewall->resource, sizeof(firewall->resource), "TCPCC_%s", random);
		if (tcpcc_iptables_command(config, firewall->command,
					    sizeof(firewall->command)))
			return tcpcc_error("invalid iptables executable selection");
		{
			char save_command[48];
			char *save[] = { save_command, "-t", "nat", NULL };

			snprintf(save_command, sizeof(save_command), "%s-save",
				 firewall->command);
			if (tcpcc_capture(save, ownership, sizeof(ownership)) ||
			    tcpcc_check_ownership_text(ownership))
				return tcpcc_error("iptables ownership inspection failed");
		}
		if (tcpcc_firewall_install_iptables(firewall))
			return tcpcc_error("installing iptables DNAT policy failed");
	} else {
		snprintf(firewall->resource, sizeof(firewall->resource), "tcpcc_%s", random);
		strcpy(family, config->listen.version == 4 ? "ip" : "ip6");
		if (config->firewall == TCPCC_FIREWALL_NFT_LIB) {
			char command[32];

			snprintf(command, sizeof(command), "list ruleset %s\n", family);
			if (tcpcc_nft_lib_capture(command, ownership, sizeof(ownership)) ||
			    tcpcc_check_ownership_text(ownership))
				return tcpcc_error("nftables ownership inspection failed");
		} else {
			char *list[] = { "nft", "list", "ruleset", family, NULL };

			if (tcpcc_capture(list, ownership, sizeof(ownership)) ||
			    tcpcc_check_ownership_text(ownership))
				return tcpcc_error("nftables ownership inspection failed");
		}
		if (tcpcc_firewall_nft(firewall, true) ||
		    tcpcc_firewall_nft(firewall, false))
			return tcpcc_error("installing nftables DNAT policy failed");
	}
	firewall->installed = true;
	return 0;
}

static int tcpcc_firewall_close(struct tcpcc_firewall *firewall)
{
	int result = 0;

	if (!firewall->installed)
		return 0;
	if (firewall->kind != TCPCC_FIREWALL_IPTABLES) {
		char batch[128];
		const char *family = firewall->version == 4 ? "ip" : "ip6";

		snprintf(batch, sizeof(batch), "delete table %s %s\n", family,
			 firewall->resource);
		result = firewall->kind == TCPCC_FIREWALL_NFT_LIB ?
			tcpcc_nft_lib_run(batch, false) :
			tcpcc_nft_exec_run(batch, false, true);
	} else {
		char port[8];
		char prefix[INET6_ADDRSTRLEN + 5];
		char marker[128];
		char *jump[] = { firewall->command, "--wait", "-t", "nat", "-D",
			"PREROUTING", "-d", prefix, "-p", "tcp", "-m", "tcp",
			"--dport", port, "-m", "comment", "--comment", marker, "-j",
			firewall->resource, NULL };
		char *flush[] = { firewall->command, "--wait", "-t", "nat", "-F",
			firewall->resource, NULL };
		char *remove[] = { firewall->command, "--wait", "-t", "nat", "-X",
			firewall->resource, NULL };

		snprintf(port, sizeof(port), "%u", firewall->port);
		snprintf(prefix, sizeof(prefix), "%s/%u", firewall->listen,
			 firewall->version == 4 ? 32U : 128U);
		snprintf(marker, sizeof(marker), "tcpcc.owner.v1 pid=%ld start=%llu tun=%s",
			 (long)getpid(), firewall->owner_start, firewall->tun_name);
		if (tcpcc_run(jump, NULL, true)) result = -1;
		if (tcpcc_run(flush, NULL, true)) result = -1;
		if (tcpcc_run(remove, NULL, true)) result = -1;
	}
	firewall->installed = false;
	return result;
}

static int tcpcc_control_call(struct tcpcc_control_client *client, uint16_t operation,
			      int handle, uint32_t arg0, const void *data,
			      uint32_t length, struct tcpcc_control_response *response)
{
	struct tcpcc_control_error error;

	if (tcpcc_control_transact(client, operation, handle, arg0, 0, data, length,
				   response, &error)) {
		fprintf(stderr, "tcpcc: error: %s\n", error.message);
		return -1;
	}
	if (response->status) {
		fprintf(stderr, "tcpcc: error: hosted operation %u failed: %s (%d)\n",
			operation, response->status < 0 ? strerror(-response->status) :
			"invalid positive status", response->status);
		return response->status;
	}
	return 0;
}

static int tcpcc_runtime_start(const struct tcpcc_cli_config *config, int tun_fd,
			       struct tcpcc_hosted_process *process,
			       struct tcpcc_control_client *client,
			       int *ifindex, int *service_handle)
{
	struct tcpcc_control_response response;
	struct tcpcc_control_error error;
	struct tcpcc_control_hello hello;
	struct tcpcc_control_l3_config l3 = { };
	struct tcpcc_control_ip_endpoint endpoint = { };
	struct tcpcc_control_service_config service = {
		.backend_ipv4 = 0x7f000001U,
		.backend_port = config->backend.port,
		.max_connections = config->max_connections,
		.accept_batch = TCPCC_DEFAULT_ACCEPT_BATCH,
	};
	int listener;
	int result;

	if (tcpcc_hosted_process_start(process, config->kernel, config->memory_mib,
				       tun_fd, &error)) {
		fprintf(stderr, "tcpcc: error: %s\n", error.message);
		return -1;
	}
	if (tcpcc_control_client_init(client, process->request_fd, process->response_fd,
				      TCPCC_CONTROL_TIMEOUT_MS, &error))
		return -1;
	result = tcpcc_control_call(client, TCPCC_CONTROL_HELLO, 0, 0, NULL, 0,
				    &response);
	if (result || response.length != sizeof(hello))
		return tcpcc_error("hosted HELLO payload is invalid");
	memcpy(&hello, response.data, sizeof(hello));
	if (hello.control_version != TCPCC_CONTROL_VERSION ||
	    (hello.feature_bits & (TCPCC_CONTROL_FEATURE_HOSTED_SERVICE |
		TCPCC_CONTROL_FEATURE_DYNAMIC_FLOWS | TCPCC_CONTROL_FEATURE_IP_ENDPOINTS)) !=
	    (TCPCC_CONTROL_FEATURE_HOSTED_SERVICE |
		TCPCC_CONTROL_FEATURE_DYNAMIC_FLOWS | TCPCC_CONTROL_FEATURE_IP_ENDPOINTS) ||
	    config->max_connections > hello.session_limit)
		return tcpcc_error("hosted kernel lacks the required native-service ABI or capacity");
	l3.address.version = (uint8_t)config->listen.version;
	/* The hosted endpoint lives at the TUN guest address, not the public address. */
	if (inet_pton(config->listen.version == 4 ? AF_INET : AF_INET6,
		      config->tun_guest, l3.address.bytes) != 1)
		return tcpcc_error("encoding hosted TUN address failed");
	l3.prefix_len = config->listen.version == 4 ? 32 : 128;
	result = tcpcc_control_call(client, TCPCC_CONTROL_L3_ATTACH_IP,
				    TCPCC_HOSTED_TUN_FD, 0, &l3, sizeof(l3), &response);
	if (result || response.handle <= 0)
		return tcpcc_error("hosted L3 attach failed");
	*ifindex = response.handle;
	result = tcpcc_control_call(client, TCPCC_CONTROL_SOCKET_IP, 0,
				    config->listen.version, NULL, 0, &response);
	if (result || response.handle <= 0)
		return tcpcc_error("hosted listener socket creation failed");
	listener = response.handle;
	result = tcpcc_control_call(client, TCPCC_CONTROL_SET_CC, listener, 0,
				    config->cc, (uint32_t)strlen(config->cc), &response);
	if (result)
		return -1;
	result = tcpcc_control_call(client, TCPCC_CONTROL_GET_CC, listener, 0, NULL, 0,
				    &response);
	if (result || response.length != (uint32_t)strlen(config->cc) ||
	    memcmp(response.data, config->cc, response.length))
		return tcpcc_error("hosted listener congestion-control verification failed");
	endpoint.address.version = (uint8_t)config->listen.version;
	if (inet_pton(config->listen.version == 4 ? AF_INET : AF_INET6,
		      config->tun_guest, endpoint.address.bytes) != 1)
		return tcpcc_error("encoding hosted listener address failed");
	endpoint.port = config->listen.port;
	result = tcpcc_control_call(client, TCPCC_CONTROL_BIND_IP, listener, 0,
				    &endpoint, sizeof(endpoint), &response);
	if (result)
		return -1;
	result = tcpcc_control_call(client, TCPCC_CONTROL_LISTEN, listener,
				    config->backlog, NULL, 0, &response);
	if (result)
		return -1;
	result = tcpcc_control_call(client, TCPCC_CONTROL_SERVICE_START, listener, 0,
				    &service, sizeof(service), &response);
	if (result || response.handle <= 0)
		return tcpcc_error("hosted event-driven service start failed");
	*service_handle = response.handle;
	return 0;
}

static int tcpcc_service_stats(struct tcpcc_control_client *client, int handle,
			       struct tcpcc_control_service_stats *stats)
{
	struct tcpcc_control_response response;
	int result = tcpcc_control_call(client, TCPCC_CONTROL_SERVICE_STATS, handle,
					0, NULL, 0, &response);

	if (result)
		return result;
	if (response.length != sizeof(*stats))
		return tcpcc_error("hosted service returned malformed aggregate stats");
	memcpy(stats, response.data, sizeof(*stats));
	return 0;
}

static void tcpcc_emit_ready(const struct tcpcc_cli_config *config,
			     const struct tcpcc_firewall *firewall, int ifindex,
			     pid_t pid)
{
	printf("{\"backend\":\"%s:%u\",\"cc\":\"%s\",\"event\":\"ready\","
	       "\"firewall_backend\":\"%s\",\"firewall_resource\":\"%s\","
	       "\"hosted_address\":\"%s\",\"hosted_ifindex\":%d,"
	       "\"hosted_memory_mib\":%lu,\"hosted_pid\":%ld,\"listen\":\"%s%s%s:%u\","
	       "\"max_connections\":%u,\"schema\":\"%s\","
	       "\"shutdown_grace_period\":%.3f,\"tun\":\"%s\"}\n",
	       config->backend.address, config->backend.port, config->cc,
	       config->firewall_name, firewall->resource, config->tun_guest, ifindex,
	       config->memory_mib, (long)pid,
	       config->listen.version == 6 ? "[" : "", config->listen.address,
	       config->listen.version == 6 ? "]" : "", config->listen.port,
	       config->max_connections, TCPCC_EVENT_SCHEMA,
	       (double)config->grace_ms / 1000.0, config->tun_name);
	fflush(stdout);
}

static void tcpcc_emit_stats(const char *event,
			     const struct tcpcc_control_service_stats *stats,
			     const struct tcpcc_cli_config *config)
{
	printf("{\"accept_eagain\":%u,\"accepted_connections\":%llu,"
	       "\"active_connections\":%u,\"backend_to_public_bytes\":%llu,"
	       "\"bridge_start_failures\":%u,\"completed_connections\":%llu,"
	       "\"event\":\"%s\",\"grace_period\":%.3f,"
	       "\"last_error\":%d,"
	       "\"max_connections\":%u,\"peak_connections\":%u,"
	       "\"public_to_backend_bytes\":%llu,\"rejected_connections\":%llu,"
	       "\"schema\":\"%s\",\"terminal_failures\":%u}\n",
	       stats->accept_eagain,
	       (unsigned long long)stats->accepted_connections,
	       stats->active_connections,
	       (unsigned long long)stats->backend_to_public_bytes,
	       stats->bridge_start_failures,
	       (unsigned long long)stats->completed_connections, event,
	       (double)config->grace_ms / 1000.0, stats->last_error,
	       stats->max_connections,
	       stats->peak_connections,
	       (unsigned long long)stats->public_to_backend_bytes,
	       (unsigned long long)stats->rejected_connections,
	       TCPCC_EVENT_SCHEMA, stats->terminal_failures);
	fflush(stdout);
}

static int tcpcc_wait_signal_or_child(struct tcpcc_hosted_process *process,
				      int signal_fd, int *requested_signal)
{
	struct tcpcc_event_loop loop = { .epoll_fd = -1 };
	struct tcpcc_control_error error;
	struct tcpcc_event events[2];
	int result;

	if (tcpcc_event_loop_init(&loop, &error) ||
	    tcpcc_event_loop_add(&loop, signal_fd, EPOLLIN, TCPCC_SIGNAL_TOKEN, &error))
		return tcpcc_error(error.message);
	if (process->pid_fd < 0 ||
	    tcpcc_event_loop_add(&loop, process->pid_fd, EPOLLIN, TCPCC_CHILD_TOKEN,
				 &error)) {
		tcpcc_event_loop_close(&loop);
		return tcpcc_error(error.message);
	}
	for (;;) {
		result = tcpcc_event_loop_wait(&loop, events, 2, -1, &error);
		if (result < 0) {
			tcpcc_event_loop_close(&loop);
			return tcpcc_error(error.message);
		}
		for (int index = 0; index < result; index++) {
			if (events[index].token == TCPCC_SIGNAL_TOKEN) {
				struct signalfd_siginfo info;

				if (read(signal_fd, &info, sizeof(info)) == sizeof(info)) {
					*requested_signal = (int)info.ssi_signo;
					tcpcc_event_loop_close(&loop);
					return 0;
				}
			} else if (events[index].token == TCPCC_CHILD_TOKEN) {
				tcpcc_event_loop_close(&loop);
				return tcpcc_error("hosted kernel exited unexpectedly");
			}
		}
	}
}

static int tcpcc_shutdown_runtime(const struct tcpcc_cli_config *config,
				  struct tcpcc_hosted_process *process,
				  struct tcpcc_control_client *client,
				  int service_handle,
				  struct tcpcc_control_service_stats *final_stats)
{
	struct tcpcc_control_response response;
	struct tcpcc_control_service_stats stats = { };
	uint32_t grace = config->grace_ms ? config->grace_ms : 1U;
	int result;

	if (tcpcc_service_stats(client, service_handle, &stats))
		return -1;
	tcpcc_emit_stats("draining", &stats, config);
	result = tcpcc_control_call(client, TCPCC_CONTROL_SERVICE_DRAIN,
				    service_handle, grace, NULL, 0, &response);
	if (result == -ETIMEDOUT) {
		printf("{\"active_connections\":%u,\"event\":\"drain-timeout\","
		       "\"grace_period\":%.3f,\"schema\":\"%s\"}\n",
		       stats.active_connections, (double)config->grace_ms / 1000.0,
		       TCPCC_EVENT_SCHEMA);
		fflush(stdout);
	} else if (result) {
		return -1;
	}
	result = tcpcc_control_call(client, TCPCC_CONTROL_SERVICE_STOP,
				    service_handle, TCPCC_CONTROL_TIMEOUT_MS, NULL, 0,
				    &response);
	if (result || response.length != sizeof(*final_stats))
		return tcpcc_error("hosted service stop returned malformed stats");
	memcpy(final_stats, response.data, sizeof(*final_stats));
	/* A terminal SHUTDOWN operation asks vmlinux to leave its host loop. */
	if (tcpcc_control_call(client, TCPCC_CONTROL_SHUTDOWN, 0, 0, NULL, 0,
			       &response))
		return -1;
	tcpcc_hosted_process_close_channels(process);
	return 0;
}

int main(int argc, char **argv)
{
	struct tcpcc_cli_config config;
	struct tcpcc_firewall firewall = { };
	struct tcpcc_hosted_process process = {
		.pid = -1, .pid_fd = -1, .request_fd = -1, .response_fd = -1,
	};
	struct tcpcc_control_client client;
	struct tcpcc_control_service_stats final_stats = { };
	sigset_t mask;
	int signal_fd = -1;
	int tun_fd = -1;
	int ifindex = 0;
	int service_handle = 0;
	int requested_signal = 0;
	int wait_status = 0;
	int result = 1;
	bool runtime_stopped = false;

	if (tcpcc_parse_args(argc, argv, &config) || tcpcc_preflight(&config))
		return 1;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, NULL)) {
		tcpcc_errno("blocking shutdown signals");
		return 1;
	}
	signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (signal_fd < 0) {
		tcpcc_errno("creating signal fd");
		goto cleanup;
	}
	tun_fd = tcpcc_tun_open(&config);
	if (tun_fd < 0)
		goto cleanup;
	if (tcpcc_firewall_install(&config, &firewall))
		goto cleanup;
	if (tcpcc_runtime_start(&config, tun_fd, &process, &client, &ifindex,
				&service_handle))
		goto cleanup;
	tcpcc_emit_ready(&config, &firewall, ifindex, process.pid);
	fprintf(stderr, "tcpcc: ready on %s:%u with %s; native service via %s\n",
		config.listen.address, config.listen.port, config.cc, config.tun_name);
	if (tcpcc_wait_signal_or_child(&process, signal_fd, &requested_signal))
		goto cleanup;
	if (tcpcc_shutdown_runtime(&config, &process, &client, service_handle,
				   &final_stats))
		goto cleanup;
	runtime_stopped = true;
	if (process.pid > 0 && tcpcc_hosted_process_wait(&process, &wait_status, NULL))
		goto cleanup;
	if (!WIFEXITED(wait_status) || WEXITSTATUS(wait_status)) {
		tcpcc_error("hosted kernel did not exit cleanly");
		goto cleanup;
	}
	result = 0;
cleanup:
	if (process.pid > 0 && !runtime_stopped) {
		struct tcpcc_control_response ignored;

		if (service_handle > 0)
			tcpcc_control_call(&client, TCPCC_CONTROL_SERVICE_STOP,
					   service_handle, TCPCC_CONTROL_TIMEOUT_MS,
					   NULL, 0, &ignored);
		tcpcc_hosted_process_signal(&process, SIGKILL, NULL);
		tcpcc_hosted_process_close_channels(&process);
		tcpcc_hosted_process_wait(&process, NULL, NULL);
	}
	if (tcpcc_firewall_close(&firewall))
		result = 1;
	if (tun_fd >= 0)
		close(tun_fd);
	if (signal_fd >= 0)
		close(signal_fd);
	if (!result) {
		tcpcc_emit_stats("service-stats", &final_stats, &config);
		printf("{\"clean\":true,\"event\":\"stopped\",\"schema\":\"%s\","
		       "\"signal\":%d}\n", TCPCC_EVENT_SCHEMA, requested_signal);
		fflush(stdout);
		fprintf(stderr, "tcpcc: stopped cleanly\n");
	}
	return result;
}

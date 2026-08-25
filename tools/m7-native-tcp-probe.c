// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHUNK_SIZE 16384U

static void die(const char *what)
{
	perror(what);
	exit(EXIT_FAILURE);
}

static uint64_t parse_u64(const char *value, const char *name)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, 10);
	if (errno || !end || *end != '\0') {
		fprintf(stderr, "invalid %s: %s\n", name, value);
		exit(EXIT_FAILURE);
	}
	return (uint64_t)parsed;
}

static uint16_t parse_port(const char *value)
{
	uint64_t port = parse_u64(value, "port");

	if (!port || port > 65535) {
		fprintf(stderr, "port out of range: %s\n", value);
		exit(EXIT_FAILURE);
	}
	return (uint16_t)port;
}

static unsigned char pattern_byte(uint64_t offset, unsigned char seed)
{
	return (unsigned char)(seed + (offset * 131U) + (offset >> 8));
}

static void send_pattern(int fd, uint64_t total, unsigned char seed)
{
	unsigned char buffer[CHUNK_SIZE];
	uint64_t offset = 0;

	while (offset < total) {
		size_t want = sizeof(buffer);
		size_t done = 0;
		size_t i;

		if (total - offset < want)
			want = (size_t)(total - offset);
		for (i = 0; i < want; i++)
			buffer[i] = pattern_byte(offset + i, seed);
		while (done < want) {
			ssize_t ret = send(fd, buffer + done, want - done, 0);

			if (ret < 0) {
				if (errno == EINTR)
					continue;
				die("send");
			}
			if (!ret) {
				fprintf(stderr, "unexpected zero-length send\n");
				exit(EXIT_FAILURE);
			}
			done += (size_t)ret;
		}
		offset += want;
	}
}

static void recv_pattern(int fd, uint64_t total, unsigned char seed)
{
	unsigned char buffer[CHUNK_SIZE];
	uint64_t offset = 0;

	while (offset < total) {
		size_t want = sizeof(buffer);
		ssize_t ret;
		size_t i;

		if (total - offset < want)
			want = (size_t)(total - offset);
		ret = recv(fd, buffer, want, 0);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			die("recv");
		}
		if (!ret) {
			fprintf(stderr, "peer closed at byte %" PRIu64 " of %" PRIu64 "\n",
				offset, total);
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < (size_t)ret; i++) {
			unsigned char expected = pattern_byte(offset + i, seed);

			if (buffer[i] != expected) {
				fprintf(stderr,
					"payload mismatch at byte %" PRIu64 ": got=%u expected=%u\n",
					offset + i, buffer[i], expected);
				exit(EXIT_FAILURE);
			}
		}
		offset += (uint64_t)ret;
	}
}

static struct sockaddr_in make_addr(const char *ip, uint16_t port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};

	if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
		fprintf(stderr, "invalid IPv4 address: %s\n", ip);
		exit(EXIT_FAILURE);
	}
	return addr;
}

static int make_socket(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0)
		die("socket");
	return fd;
}

static void run_server(const char *ip, uint16_t port, uint64_t rx_bytes,
		       uint64_t tx_bytes)
{
	struct sockaddr_in addr = make_addr(ip, port);
	int listener = make_socket();
	int one = 1;
	int client;
	unsigned char byte;
	ssize_t ret;

	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		die("setsockopt(SO_REUSEADDR)");
	if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("bind");
	if (listen(listener, 1) < 0)
		die("listen");
	client = accept(listener, NULL, NULL);
	if (client < 0)
		die("accept");

	recv_pattern(client, rx_bytes, 0x11);
	send_pattern(client, tx_bytes, 0xa7);

	/* Keep the server side established until the client snapshots TCP_INFO. */
	do {
		ret = recv(client, &byte, sizeof(byte), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0)
		die("recv(wait-for-client-close)");
	if (ret > 0) {
		fprintf(stderr, "unexpected client data after transfer\n");
		exit(EXIT_FAILURE);
	}

	close(client);
	close(listener);
}

static void connect_with_retry(int fd, const struct sockaddr_in *addr)
{
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000L };
	int attempt;

	for (attempt = 0; attempt < 200; attempt++) {
		if (!connect(fd, (const struct sockaddr *)addr, sizeof(*addr)))
			return;
		if (errno != ECONNREFUSED && errno != EINTR)
			die("connect");
		nanosleep(&delay, NULL);
	}
	fprintf(stderr, "connect timed out\n");
	exit(EXIT_FAILURE);
}

static void select_cc(int fd, const char *cc)
{
	char selected[32] = {};
	socklen_t len = sizeof(selected);

	if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, cc, strlen(cc)) < 0)
		die("setsockopt(TCP_CONGESTION)");
	if (getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, selected, &len) < 0)
		die("getsockopt(TCP_CONGESTION)");
	if (strcmp(selected, cc)) {
		fprintf(stderr, "selected congestion control mismatch: requested=%s got=%s\n",
			cc, selected);
		exit(EXIT_FAILURE);
	}
}

static void print_tcp_info(int fd, const char *cc, uint64_t tx_bytes,
			   uint64_t rx_bytes)
{
	struct tcp_info info = {};
	socklen_t len = sizeof(info);

	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) < 0)
		die("getsockopt(TCP_INFO)");
	printf("%s: guest_to_host=%" PRIu64 " host_to_guest=%" PRIu64
	       " state=%u ca_state=%u rto_us=%u rtt_us=%u rttvar_us=%u"
	       " snd_cwnd=%u snd_ssthresh=%u unacked=%u lost=%u retrans=%u"
	       " total_retrans=%u pacing_rate=%" PRIu64
	       " max_pacing_rate=%" PRIu64 " delivery_rate=%" PRIu64 "\n",
	       cc, tx_bytes, rx_bytes, info.tcpi_state, info.tcpi_ca_state,
	       info.tcpi_rto, info.tcpi_rtt, info.tcpi_rttvar, info.tcpi_snd_cwnd,
	       info.tcpi_snd_ssthresh, info.tcpi_unacked, info.tcpi_lost,
	       info.tcpi_retrans, info.tcpi_total_retrans,
	       (uint64_t)info.tcpi_pacing_rate,
	       (uint64_t)info.tcpi_max_pacing_rate,
	       (uint64_t)info.tcpi_delivery_rate);
	fflush(stdout);
}

static void run_client(const char *ip, uint16_t port, const char *cc,
		       uint64_t tx_bytes, uint64_t rx_bytes)
{
	struct sockaddr_in addr = make_addr(ip, port);
	int fd = make_socket();

	select_cc(fd, cc);
	connect_with_retry(fd, &addr);
	send_pattern(fd, tx_bytes, 0x11);
	recv_pattern(fd, rx_bytes, 0xa7);
	print_tcp_info(fd, cc, tx_bytes, rx_bytes);
	close(fd);
}

int main(int argc, char **argv)
{
	if (argc == 6 && !strcmp(argv[1], "server")) {
		run_server(argv[2], parse_port(argv[3]), parse_u64(argv[4], "rx-bytes"),
			   parse_u64(argv[5], "tx-bytes"));
		return 0;
	}
	if (argc == 7 && !strcmp(argv[1], "client")) {
		run_client(argv[2], parse_port(argv[3]), argv[4],
			   parse_u64(argv[5], "tx-bytes"),
			   parse_u64(argv[6], "rx-bytes"));
		return 0;
	}
	fprintf(stderr,
		"usage: %s server IP PORT RX_BYTES TX_BYTES\n"
		"       %s client IP PORT CC TX_BYTES RX_BYTES\n",
		argv[0], argv[0]);
	return EXIT_FAILURE;
}

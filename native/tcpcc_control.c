// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include "tcpcc_control.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(struct tcpcc_control_request) == 280,
	       "tcpcc request ABI drift");
_Static_assert(sizeof(struct tcpcc_control_response) == 276,
	       "tcpcc response ABI drift");
_Static_assert(sizeof(struct tcpcc_control_tcp_info) == 64,
	       "tcpcc TCP info ABI drift");
_Static_assert(sizeof(struct tcpcc_control_host_backend_result) == 32,
	       "tcpcc host-backend ABI drift");
_Static_assert(sizeof(struct tcpcc_bridge_result) == 64,
	       "tcpcc bridge-result ABI drift");
_Static_assert(sizeof(struct tcpcc_control_hello) == 88,
	       "tcpcc hello ABI drift");
_Static_assert(sizeof(struct tcpcc_control_service_config) == 16,
	       "tcpcc service-config ABI drift");
_Static_assert(sizeof(struct tcpcc_control_service_stats) == 88,
	       "tcpcc service-stats ABI drift");
_Static_assert(sizeof(struct tcpcc_control_ip_address) == 20,
	       "tcpcc IP-address ABI drift");
_Static_assert(sizeof(struct tcpcc_control_ip_endpoint) == 24,
	       "tcpcc IP-endpoint ABI drift");
_Static_assert(sizeof(struct tcpcc_control_l3_config) == 24,
	       "tcpcc L3-config ABI drift");

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the tcpcc version-1 control ABI requires a little-endian host"
#endif

static int tcpcc_control_fail(struct tcpcc_control_error *error, int code,
			      const char *format, ...)
{
	va_list arguments;

	if (error) {
		error->code = code;
		va_start(arguments, format);
		vsnprintf(error->message, sizeof(error->message), format, arguments);
		va_end(arguments);
	}
	return -1;
}

static int64_t tcpcc_control_now_ms(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return -1;
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int tcpcc_control_wait(int fd, short events, int64_t deadline,
			      struct tcpcc_control_error *error)
{
	struct pollfd descriptor = {
		.fd = fd,
		.events = events,
	};

	for (;;) {
		int64_t now = tcpcc_control_now_ms();
		int timeout;
		int result;

		if (now < 0)
			return tcpcc_control_fail(error, errno,
				"clock_gettime(CLOCK_MONOTONIC) failed: %s",
				strerror(errno));
		if (now >= deadline)
			return tcpcc_control_fail(error, ETIMEDOUT,
				"hosted control transaction timed out");
		timeout = deadline - now > INT_MAX ? INT_MAX : (int)(deadline - now);
		descriptor.revents = 0;
		result = poll(&descriptor, 1, timeout);
		if (result < 0 && errno == EINTR)
			continue;
		if (result < 0)
			return tcpcc_control_fail(error, errno,
				"poll on hosted control fd %d failed: %s",
				fd, strerror(errno));
		if (!result)
			return tcpcc_control_fail(error, ETIMEDOUT,
				"hosted control transaction timed out");
		if (descriptor.revents & (POLLERR | POLLNVAL))
			return tcpcc_control_fail(error, EIO,
				"hosted control fd %d reported events 0x%x",
				fd, descriptor.revents);
		if (descriptor.revents & events)
			return 0;
		if (descriptor.revents & POLLHUP)
			return tcpcc_control_fail(error, EPIPE,
				"hosted control fd %d closed", fd);
	}
}

static int tcpcc_control_write_exact(int fd, const void *buffer, size_t length,
				     int64_t deadline,
				     struct tcpcc_control_error *error)
{
	const unsigned char *cursor = buffer;
	size_t written = 0;

	while (written < length) {
		ssize_t result;

		if (tcpcc_control_wait(fd, POLLOUT, deadline, error) != 0)
			return -1;
		result = write(fd, cursor + written, length - written);
		if (result < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (result < 0)
			return tcpcc_control_fail(error, errno,
				"write to hosted control fd failed: %s",
				strerror(errno));
		if (!result)
			return tcpcc_control_fail(error, EPIPE,
				"write to hosted control fd returned zero");
		written += (size_t)result;
	}
	return 0;
}

static int tcpcc_control_read_exact(int fd, void *buffer, size_t length,
				    int64_t deadline,
				    struct tcpcc_control_error *error)
{
	unsigned char *cursor = buffer;
	size_t received = 0;

	while (received < length) {
		ssize_t result;

		if (tcpcc_control_wait(fd, POLLIN, deadline, error) != 0)
			return -1;
		result = read(fd, cursor + received, length - received);
		if (result < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (result < 0)
			return tcpcc_control_fail(error, errno,
				"read from hosted control fd failed: %s",
				strerror(errno));
		if (!result)
			return tcpcc_control_fail(error, EPIPE,
				"hosted control response ended after %zu/%zu bytes",
				received, length);
		received += (size_t)result;
	}
	return 0;
}

int tcpcc_control_client_init(struct tcpcc_control_client *client,
			      int request_fd, int response_fd,
			      int timeout_ms,
			      struct tcpcc_control_error *error)
{
	if (!client)
		return tcpcc_control_fail(error, EINVAL,
			"control client pointer is null");
	if (request_fd < 0 || response_fd < 0 || timeout_ms <= 0)
		return tcpcc_control_fail(error, EINVAL,
			"control fds and timeout must be positive");
	client->request_fd = request_fd;
	client->response_fd = response_fd;
	client->timeout_ms = timeout_ms;
	if (error) {
		error->code = 0;
		error->message[0] = '\0';
	}
	return 0;
}

int tcpcc_control_transact(struct tcpcc_control_client *client,
			   uint16_t operation, int32_t handle,
			   uint32_t arg0, uint32_t arg1,
			   const void *data, uint32_t length,
			   struct tcpcc_control_response *response,
			   struct tcpcc_control_error *error)
{
	struct tcpcc_control_request request = {
		.magic = TCPCC_CONTROL_MAGIC,
		.version = TCPCC_CONTROL_VERSION,
		.op = operation,
		.handle = handle,
		.arg0 = arg0,
		.arg1 = arg1,
		.length = length,
	};
	int64_t now;
	int64_t deadline;

	if (!client || !response || !operation)
		return tcpcc_control_fail(error, EINVAL,
			"control transaction arguments are invalid");
	if (length > TCPCC_CONTROL_MAX_PAYLOAD || (length && !data))
		return tcpcc_control_fail(error, EMSGSIZE,
			"control payload length %u is invalid", length);
	if (length)
		memcpy(request.data, data, length);

	now = tcpcc_control_now_ms();
	if (now < 0)
		return tcpcc_control_fail(error, errno,
			"clock_gettime(CLOCK_MONOTONIC) failed: %s",
			strerror(errno));
	deadline = now + client->timeout_ms;
	if (tcpcc_control_write_exact(client->request_fd, &request,
				       sizeof(request), deadline, error) != 0)
		return -1;
	if (tcpcc_control_read_exact(client->response_fd, response,
				      sizeof(*response), deadline, error) != 0)
		return -1;

	if (response->magic != TCPCC_CONTROL_MAGIC)
		return tcpcc_control_fail(error, EPROTO,
			"hosted response magic is 0x%08x", response->magic);
	if (response->version != TCPCC_CONTROL_VERSION)
		return tcpcc_control_fail(error, EPROTO,
			"hosted response version is %u, expected %u",
			response->version, TCPCC_CONTROL_VERSION);
	if (response->op != operation)
		return tcpcc_control_fail(error, EPROTO,
			"hosted response operation is %u, expected %u",
			response->op, operation);
	if (response->length > TCPCC_CONTROL_MAX_PAYLOAD)
		return tcpcc_control_fail(error, EPROTO,
			"hosted response payload length is %u", response->length);
	if (error) {
		error->code = 0;
		error->message[0] = '\0';
	}
	return 0;
}

/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_CONTROL_ABI_H
#define _ASM_TCPCC_CONTROL_ABI_H

#include <linux/types.h>

/*
 * Stable host <-> hosted-kernel control ABI.
 *
 * ARCH=tcpcc currently runs only as a little-endian x86-64 host process.
 * All records nevertheless use fixed-width fields and have compile-time size
 * assertions on both sides of the boundary.  New operations and feature bits
 * are append-only within a control version.
 */
#define TCPCC_CONTROL_MAGIC        0x32434354U /* "TCC2" on x86-64 */
#define TCPCC_CONTROL_VERSION      1U
#define TCPCC_CONTROL_MAX_PAYLOAD  256U

enum tcpcc_control_op {
	TCPCC_CONTROL_SOCKET = 1,
	TCPCC_CONTROL_BIND,
	TCPCC_CONTROL_LISTEN,
	TCPCC_CONTROL_CONNECT,
	TCPCC_CONTROL_ACCEPT,
	TCPCC_CONTROL_WRITE,
	TCPCC_CONTROL_READ,
	TCPCC_CONTROL_CLOSE,
	TCPCC_CONTROL_SET_CC,
	TCPCC_CONTROL_GET_CC,
	TCPCC_CONTROL_FINISH,
	TCPCC_CONTROL_L3_ATTACH,
	TCPCC_CONTROL_L3_STATS,
	TCPCC_CONTROL_TCP_INFO,
	TCPCC_CONTROL_HOST_BACKEND_PROBE,
	TCPCC_CONTROL_BRIDGE_START,
	TCPCC_CONTROL_BRIDGE_JOIN,
	TCPCC_CONTROL_BRIDGE_CANCEL,
	TCPCC_CONTROL_ACCEPT_NONBLOCK,
	TCPCC_CONTROL_SHUTDOWN,
	TCPCC_CONTROL_BRIDGE_JOIN_RESULT,
	TCPCC_CONTROL_HELLO,
	TCPCC_CONTROL_SERVICE_START,
	TCPCC_CONTROL_SERVICE_DRAIN,
	TCPCC_CONTROL_SERVICE_STATS,
	TCPCC_CONTROL_SERVICE_STOP,
};

/* Capabilities returned by TCPCC_CONTROL_HELLO. */
#define TCPCC_CONTROL_FEATURE_BRIDGE_RESULT (1U << 0)
#define TCPCC_CONTROL_FEATURE_HOSTED_SERVICE (1U << 1)

struct tcpcc_control_request {
	__u32 magic;
	__u16 version;
	__u16 op;
	__s32 handle;
	__u32 arg0;
	__u32 arg1;
	__u32 length;
	__u8 data[TCPCC_CONTROL_MAX_PAYLOAD];
};

struct tcpcc_control_response {
	__u32 magic;
	__u16 version;
	__u16 op;
	__s32 status;
	__s32 handle;
	__u32 length;
	__u8 data[TCPCC_CONTROL_MAX_PAYLOAD];
};

/*
 * Stable project-side subset of Linux struct tcp_info.  Keep this independent
 * of the upstream UAPI struct's future growth.
 */
struct tcpcc_control_tcp_info {
	__u8 state;
	__u8 ca_state;
	__u16 reserved;
	__u32 rto_us;
	__u32 rtt_us;
	__u32 rttvar_us;
	__u32 snd_cwnd;
	__u32 snd_ssthresh;
	__u32 unacked;
	__u32 lost;
	__u32 retrans;
	__u32 total_retrans;
	__u64 pacing_rate;
	__u64 max_pacing_rate;
	__u64 delivery_rate;
};

struct tcpcc_control_host_backend_result {
	__u64 token;
	__s32 connect_status;
	__u32 connect_events;
	__u32 terminal_events;
	__u32 tx_bytes;
	__u32 rx_bytes;
	__u32 reserved;
};

/* Fixed 64-byte terminal bridge snapshot returned by join-result. */
struct tcpcc_bridge_result {
	__u64 token;
	__u64 public_to_backend_bytes;
	__u64 backend_to_public_bytes;
	__u32 buffer_limit;
	__u32 total_buffer_limit;
	__u32 terminal_events;
	__u32 host_send_eagain;
	__u32 host_partial_writes;
	__u32 host_recv_eagain;
	__u32 session_limit;
	__s32 status;
	__u32 reserved[2];
};

#define TCPCC_CONTROL_RELEASE_LENGTH 64U

/*
 * Version-1 capability handshake.  A future event-driven service ABI will be
 * advertised with new feature bits without making a native host guess limits
 * from build-time constants.
 */
struct tcpcc_control_hello {
	__u32 control_version;
	__u32 feature_bits;
	__u32 session_limit;
	__u32 bridge_buffer_limit;
	__u32 bridge_total_buffer_limit;
	__u32 reserved;
	char linux_release[TCPCC_CONTROL_RELEASE_LENGTH];
};

/* Payload for SERVICE_START; the listener is supplied in request.handle. */
struct tcpcc_control_service_config {
	__u32 backend_ipv4;
	__u16 backend_port;
	__u16 reserved;
	__u32 max_connections;
	__u32 accept_batch;
};

enum tcpcc_control_service_state {
	TCPCC_CONTROL_SERVICE_STOPPED = 0,
	TCPCC_CONTROL_SERVICE_RUNNING,
	TCPCC_CONTROL_SERVICE_DRAINING,
	TCPCC_CONTROL_SERVICE_STOPPING,
	TCPCC_CONTROL_SERVICE_FAILED,
};

/* Fixed 88-byte aggregate snapshot; no per-flow hot-path reporting. */
struct tcpcc_control_service_stats {
	__u64 accepted_connections;
	__u64 completed_connections;
	__u64 rejected_connections;
	__u64 public_to_backend_bytes;
	__u64 backend_to_public_bytes;
	__u32 active_connections;
	__u32 peak_connections;
	__u32 max_connections;
	__u32 accept_batch;
	__u32 accept_eagain;
	__u32 bridge_start_failures;
	__u32 terminal_failures;
	__u32 state;
	__s32 last_error;
	__u32 reserved[3];
};

#endif /* _ASM_TCPCC_CONTROL_ABI_H */

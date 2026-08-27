#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise hosted Linux ICMP and native TCP/CC through a real host TUN queue."""

import argparse
import errno
import fcntl
import importlib.util
import os
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path

BASE = Path(__file__).with_name("run-tcpcc-control-test.py")
SPEC = importlib.util.spec_from_file_location("tcpcc_control_test", BASE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {BASE}")

control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)

# linux/if_tun.h and linux/if.h values for the project's x86-64 host ABI.
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
IFREQ_SIZE = 40
IFNAMSIZ = 16

HOST_IPV4 = "192.0.2.1"
HOST_IPV4_U32 = 0xC0000201
GUEST_IPV4 = "192.0.2.2"
GUEST_IPV4_U32 = 0xC0000202
GUEST_PREFIX = 24
SMALL_PING_COUNT = 32
SMALL_PING_PAYLOAD = 68       # 20-byte IPv4 + 8-byte ICMP + 68 = 96 bytes.
MTU_PING_PAYLOAD = 1472       # 20 + 8 + 1472 = 1500 bytes.
OVERSIZE_PING_PAYLOAD = 1473  # 20 + 8 + 1473 = 1501 bytes.
DEFAULT_TCP_TRANSFER_BYTES = 16 * 1024
TCP_CHUNK_BYTES = control.MAX_PAYLOAD
HOST_DRAIN_TIMEOUT = 30.0
INBOUND_TCP_PORTS = {
    "cubic": 18443,
    "bbr": 18444,
}
BRIDGE_TCP_PORT = 18445
BRIDGE_CONCURRENT_PORTS = {
    "fast-cubic": 18446,
    "delayed-bbr": 18447,
    "reuse-cubic": 18448,
}
BRIDGE_CANCEL_PORTS = {
    "victim-bbr": 18449,
    "survivor-cubic": 18450,
    "replacement-cubic": 18451,
    "finish-bbr": 18452,
}
BRIDGE_CAPACITY_PORT_BASE = 18460
BRIDGE_CAPACITY_OVERFLOW_PORT = 18468
BRIDGE_CAPACITY_REPLACEMENT_PORT = 18469
BRIDGE_RESET_PORTS = {
    "survivor-cubic": 18470,
    "backend-bbr": 18471,
    "public-bbr": 18472,
}
HOSTED_SERVICE_PORT = 18473
BRIDGE_SESSION_LIMIT = 8
BRIDGE_RUNTIME_SLOT_BASE = 2
BRIDGE_HANDLE_SLOT_BITS = 4
BRIDGE_HANDLE_SLOT_MASK = 0x0F
BRIDGE_HANDLE_GENERATION_MASK = 0x07FFFFFF
BRIDGE_BUFFER_LIMIT = 16 * 1024
BRIDGE_TOTAL_BUFFER_LIMIT = 2 * BRIDGE_SESSION_LIMIT * BRIDGE_BUFFER_LIMIT
BRIDGE_TRANSFER_BYTES = 4 * BRIDGE_BUFFER_LIMIT + 123
BRIDGE_FAST_BYTES = 8 * BRIDGE_BUFFER_LIMIT + 211
BRIDGE_DELAYED_BYTES = 32 * BRIDGE_BUFFER_LIMIT + 123
BRIDGE_REUSE_BYTES = 4 * BRIDGE_BUFFER_LIMIT + 157
BRIDGE_CANCEL_VICTIM_BYTES = 8 * BRIDGE_BUFFER_LIMIT + 173
BRIDGE_CANCEL_SURVIVOR_BYTES = 6 * BRIDGE_BUFFER_LIMIT + 191
BRIDGE_CANCEL_REPLACEMENT_BYTES = 4 * BRIDGE_BUFFER_LIMIT + 197
BRIDGE_FINISH_CANCEL_BYTES = 4 * BRIDGE_BUFFER_LIMIT + 223
BRIDGE_CAPACITY_BYTES = 2 * BRIDGE_BUFFER_LIMIT + 229
BRIDGE_RESET_SURVIVOR_BYTES = 4 * BRIDGE_BUFFER_LIMIT + 233
BRIDGE_PUBLIC_RESET_BYTES = 2 * BRIDGE_BUFFER_LIMIT + 239
BRIDGE_JOIN_TIMEOUT_MS = 5000
OP_BRIDGE_JOIN_RESULT = 21
OP_SERVICE_START = 23
OP_SERVICE_DRAIN = 24
OP_SERVICE_STATS = 25
OP_SERVICE_STOP = 26

# Appended version-1 control ABI operation. Keep the unpack layout synchronized
# with struct tcpcc_control_tcp_info in arch/tcpcc/kernel/control.c.
OP_TCP_INFO = 14
TCP_INFO = struct.Struct("<BBHIIIIIIIIIQQQ")
TCP_ESTABLISHED = 1
# Keep synchronized with struct tcpcc_bridge_result in asm/bridge.h.
BRIDGE_RESULT = struct.Struct("<QQQIIIIIIIiII")
SERVICE_CONFIG = struct.Struct("<IHHII")
SERVICE_STATS = struct.Struct("<QQQQQIIIIIIIIiIII")
SERVICE_STOPPED = 0
SERVICE_DRAINING = 2


def attach_tun_queue(name: str) -> int:
    encoded = name.encode("ascii")
    if not encoded or len(encoded) >= IFNAMSIZ:
        raise ValueError(f"invalid TUN interface name {name!r}")

    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    ifr = bytearray(IFREQ_SIZE)
    struct.pack_into("16sH", ifr, 0, encoded, IFF_TUN | IFF_NO_PI)
    try:
        fcntl.ioctl(fd, TUNSETIFF, ifr, True)
    except Exception:
        os.close(fd)
        raise

    actual = bytes(ifr[:IFNAMSIZ]).split(b"\0", 1)[0].decode("ascii")
    if actual != name:
        os.close(fd)
        raise RuntimeError(f"TUNSETIFF attached {actual!r}, expected {name!r}")
    return fd


def append_command(log: list[str], command: list[str], *, expect_success: bool) -> int:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=15,
        check=False,
    )
    log.append(f"$ {' '.join(command)}\n{completed.stdout}")
    if expect_success and completed.returncode != 0:
        raise RuntimeError(
            f"command failed with {completed.returncode}: {' '.join(command)}"
        )
    return completed.returncode


def ping_command(name: str, count: int, payload: int, *, df: bool = False) -> list[str]:
    command = [
        "ping", "-4", "-n", "-q", "-I", name,
        "-c", str(count), "-i", "0.05", "-W", "1",
    ]
    if df:
        command += ["-M", "do"]
    command += ["-s", str(payload), GUEST_IPV4]
    return command


def query_stats(proc: subprocess.Popen, responses: bytearray) -> tuple[int, ...]:
    _, length, raw_stats = control.transact(
        proc,
        responses,
        control.OP_L3_STATS,
        control.request(control.OP_L3_STATS),
    )
    if length != control.L3_STATS.size:
        raise RuntimeError(
            f"L3 stats size mismatch: {length} != {control.L3_STATS.size}"
        )
    return control.L3_STATS.unpack(raw_stats)


def query_tcp_info(proc: subprocess.Popen, responses: bytearray,
                   handle: int, cc_name: str) -> dict[str, int]:
    _, length, raw_info = control.transact(
        proc,
        responses,
        OP_TCP_INFO,
        control.request(OP_TCP_INFO, handle),
    )
    if length != TCP_INFO.size:
        raise RuntimeError(
            f"{cc_name}: TCP telemetry size mismatch: {length} != {TCP_INFO.size}"
        )

    (state, ca_state, _reserved, rto_us, rtt_us, rttvar_us, snd_cwnd,
     snd_ssthresh, unacked, lost, retrans, total_retrans, pacing_rate,
     max_pacing_rate, delivery_rate) = TCP_INFO.unpack(raw_info)
    if state != TCP_ESTABLISHED:
        raise RuntimeError(
            f"{cc_name}: TCP telemetry sampled state {state}, expected ESTABLISHED"
        )
    if snd_cwnd == 0:
        raise RuntimeError(f"{cc_name}: TCP telemetry reported zero snd_cwnd")

    return {
        "state": state,
        "ca_state": ca_state,
        "rto_us": rto_us,
        "rtt_us": rtt_us,
        "rttvar_us": rttvar_us,
        "snd_cwnd": snd_cwnd,
        "snd_ssthresh": snd_ssthresh,
        "unacked": unacked,
        "lost": lost,
        "retrans": retrans,
        "total_retrans": total_retrans,
        "pacing_rate": pacing_rate,
        "max_pacing_rate": max_pacing_rate,
        "delivery_rate": delivery_rate,
    }


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError(f"host TCP EOF after {len(data)}/{length} bytes")
        data.extend(chunk)
    return bytes(data)


def drain_host_socket(sock: socket.socket, length: int,
                      result: dict[str, object]) -> None:
    try:
        result["data"] = recv_exact(sock, length)
    except Exception as exc:  # Propagate reader failures on the control thread.
        result["error"] = exc


def bridge_backend_worker(listener: socket.socket, expected: bytes,
                          result: dict[str, object],
                          ready: threading.Event | None = None,
                          release: threading.Event | None = None,
                          receive_buffer: int | None = None,
                          reset_immediately: bool = False) -> None:
    """Echo after public EOF so the bridge must propagate both half-closes."""
    conn: socket.socket | None = None
    try:
        result["stage"] = "accept"
        conn, peer = listener.accept()
        conn.settimeout(HOST_DRAIN_TIMEOUT)
        if peer[0] != "127.0.0.1":
            raise RuntimeError(
                f"bridge backend accepted unexpected peer {peer[0]}"
            )
        if receive_buffer is not None:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
        if ready is not None:
            ready.set()
        if reset_immediately:
            conn.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack("ii", 1, 0),
            )
            result["stage"] = "reset"
            result["reset"] = True
            return
        result["stage"] = "release"
        if release is not None and not release.wait(HOST_DRAIN_TIMEOUT):
            raise TimeoutError("bridge backend release was not signalled")

        result["stage"] = "receive"
        received_buffer = bytearray()
        while len(received_buffer) < len(expected):
            chunk = conn.recv(len(expected) - len(received_buffer))
            if not chunk:
                raise EOFError(
                    "bridge backend EOF after "
                    f"{len(received_buffer)}/{len(expected)} bytes"
                )
            received_buffer.extend(chunk)
            result["received_bytes"] = len(received_buffer)
        received = bytes(received_buffer)
        if received != expected:
            raise RuntimeError("bridge backend payload mismatch")
        if conn.recv(1):
            raise RuntimeError("bridge backend received data after expected payload")

        result["data"] = received
        result["stage"] = "send"
        conn.sendall(received)
        conn.shutdown(socket.SHUT_WR)
        result["stage"] = "complete"
    except Exception as exc:
        result["error"] = exc
    finally:
        if ready is not None:
            ready.set()
        if conn is not None:
            conn.close()
        listener.close()


def decode_bridge_handle(handle: int, label: str) -> tuple[int, int]:
    if handle <= 0:
        raise RuntimeError(f"{label}: invalid bridge handle {handle}")
    raw = handle & 0xFFFFFFFF
    slot = raw & BRIDGE_HANDLE_SLOT_MASK
    generation = raw >> BRIDGE_HANDLE_SLOT_BITS
    if slot < 1 or slot > BRIDGE_SESSION_LIMIT:
        raise RuntimeError(f"{label}: invalid bridge handle slot {slot}")
    if generation < 1 or generation > BRIDGE_HANDLE_GENERATION_MASK:
        raise RuntimeError(
            f"{label}: invalid bridge handle generation {generation}"
        )
    return slot - 1, generation


def validate_bridge_result(handle: int, raw_result: bytes, payload: bytes,
                           label: str) -> dict[str, int]:
    (token, public_to_backend, backend_to_public, buffer_limit,
     total_buffer_limit, terminal_events, host_send_eagain,
     host_partial_writes, host_recv_eagain, session_limit,
     bridge_status, reserved0, reserved1) = BRIDGE_RESULT.unpack(raw_result)
    slot, handle_generation = decode_bridge_handle(handle, label)
    token_slot = token & 0xFFFFFFFF
    token_generation = (token >> 32) & 0x7FFFFFFF
    expected_token_slot = BRIDGE_RUNTIME_SLOT_BASE + slot
    if not token & (1 << 63) or token_slot != expected_token_slot:
        raise RuntimeError(f"{label}: invalid runtime token 0x{token:016x}")
    if token_generation != handle_generation:
        raise RuntimeError(
            f"{label}: token generation {token_generation} != "
            f"handle generation {handle_generation}"
        )
    if public_to_backend != len(payload) or backend_to_public != len(payload):
        raise RuntimeError(
            f"{label}: byte counters mismatch: "
            f"public-to-backend={public_to_backend} "
            f"backend-to-public={backend_to_public} expected={len(payload)}"
        )
    if buffer_limit != BRIDGE_BUFFER_LIMIT:
        raise RuntimeError(
            f"{label}: buffer limit {buffer_limit} != {BRIDGE_BUFFER_LIMIT}"
        )
    if total_buffer_limit != BRIDGE_TOTAL_BUFFER_LIMIT:
        raise RuntimeError(
            f"{label}: total buffer limit {total_buffer_limit} != "
            f"{BRIDGE_TOTAL_BUFFER_LIMIT}"
        )
    if session_limit != BRIDGE_SESSION_LIMIT:
        raise RuntimeError(
            f"{label}: session limit {session_limit} != {BRIDGE_SESSION_LIMIT}"
        )
    if terminal_events & control.HOST_EVENT_ERROR:
        raise RuntimeError(
            f"{label}: terminal host error mask 0x{terminal_events:x}"
        )
    if bridge_status or reserved0 or reserved1:
        raise RuntimeError(
            f"{label}: status={bridge_status} "
            f"reserved={reserved0}/{reserved1}"
        )
    return {
        "token": token,
        "slot": slot,
        "generation": handle_generation,
        "public_to_backend": public_to_backend,
        "backend_to_public": backend_to_public,
        "buffer_limit": buffer_limit,
        "total_buffer_limit": total_buffer_limit,
        "terminal_events": terminal_events,
        "host_send_eagain": host_send_eagain,
        "host_partial_writes": host_partial_writes,
        "host_recv_eagain": host_recv_eagain,
        "session_limit": session_limit,
    }


def validate_terminal_bridge_result(
    handle: int,
    raw_result: bytes,
    label: str,
) -> dict[str, int]:
    (token, public_to_backend, backend_to_public, buffer_limit,
     total_buffer_limit, terminal_events, host_send_eagain,
     host_partial_writes, host_recv_eagain, session_limit,
     bridge_status, reserved0, reserved1) = BRIDGE_RESULT.unpack(raw_result)
    slot, handle_generation = decode_bridge_handle(handle, label)
    token_slot = token & 0xFFFFFFFF
    token_generation = (token >> 32) & 0x7FFFFFFF
    if (
        not token & (1 << 63)
        or token_slot != BRIDGE_RUNTIME_SLOT_BASE + slot
        or token_generation != handle_generation
    ):
        raise RuntimeError(f"{label}: invalid terminal token 0x{token:016x}")
    if (
        buffer_limit != BRIDGE_BUFFER_LIMIT
        or total_buffer_limit != BRIDGE_TOTAL_BUFFER_LIMIT
        or session_limit != BRIDGE_SESSION_LIMIT
    ):
        raise RuntimeError(
            f"{label}: terminal resource contract changed: "
            f"buffer={buffer_limit}/{total_buffer_limit} "
            f"sessions={session_limit}"
        )
    if bridge_status >= 0:
        raise RuntimeError(
            f"{label}: reset bridge returned non-error status {bridge_status}"
        )
    if bridge_status == -errno.ECANCELED:
        raise RuntimeError(f"{label}: endpoint reset was reported as cancellation")
    if reserved0 or reserved1:
        raise RuntimeError(
            f"{label}: terminal result reserved={reserved0}/{reserved1}"
        )
    return {
        "token": token,
        "slot": slot,
        "generation": handle_generation,
        "public_to_backend": public_to_backend,
        "backend_to_public": backend_to_public,
        "terminal_events": terminal_events,
        "host_send_eagain": host_send_eagain,
        "host_partial_writes": host_partial_writes,
        "host_recv_eagain": host_recv_eagain,
        "status": bridge_status,
    }


def join_terminal_bridge(
    proc: subprocess.Popen,
    responses: bytearray,
    session: dict[str, object],
) -> dict[str, int]:
    label = str(session["label"])
    bridge_handle = int(session["bridge_handle"])
    _, length, raw_result = control.transact(
        proc,
        responses,
        OP_BRIDGE_JOIN_RESULT,
        control.request(
            OP_BRIDGE_JOIN_RESULT,
            bridge_handle,
            BRIDGE_JOIN_TIMEOUT_MS,
        ),
        {"length": BRIDGE_RESULT.size},
    )
    if length != BRIDGE_RESULT.size:
        raise RuntimeError(
            f"{label}: terminal result size {length} != {BRIDGE_RESULT.size}"
        )
    return validate_terminal_bridge_result(
        bridge_handle,
        raw_result,
        label,
    )


def exercise_external_tcp(proc: subprocess.Popen, responses: bytearray,
                          cc_name: str, guest_to_host_bytes: int,
                          host_to_guest_bytes: int) -> str:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.settimeout(control.CONTROL_TIMEOUT)
    listener.bind((HOST_IPV4, 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    guest_handle: int | None = None
    conn: socket.socket | None = None

    guest_to_host = control.make_payload(
        f"tcpcc-tun-{cc_name}-guest-to-host:".encode("ascii"),
        guest_to_host_bytes,
    )
    host_to_guest = control.make_payload(
        f"tcpcc-tun-{cc_name}-host-to-guest:".encode("ascii"),
        host_to_guest_bytes,
    )

    try:
        guest_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_SOCKET,
            control.request(control.OP_SOCKET),
        )
        if guest_handle <= 0:
            raise RuntimeError(f"{cc_name}: invalid guest socket handle {guest_handle}")

        control.transact(
            proc,
            responses,
            control.OP_SET_CC,
            control.request(control.OP_SET_CC, guest_handle, data=cc_name.encode("ascii")),
        )
        control.transact(
            proc,
            responses,
            control.OP_GET_CC,
            control.request(control.OP_GET_CC, guest_handle),
            {"data": cc_name.encode("ascii")},
        )
        control.transact(
            proc,
            responses,
            control.OP_CONNECT,
            control.request(control.OP_CONNECT, guest_handle, HOST_IPV4_U32, port),
        )

        conn, peer = listener.accept()
        conn.settimeout(control.CONTROL_TIMEOUT)
        if peer[0] != GUEST_IPV4:
            raise RuntimeError(
                f"{cc_name}: host accepted peer {peer[0]}, expected {GUEST_IPV4}"
            )

        # Drain concurrently so enlarged M6.3 transfers cannot stall merely
        # because the host application receive window fills while the control
        # thread is still issuing guest-side kernel_sendmsg() requests.
        host_result: dict[str, object] = {}
        host_reader = threading.Thread(
            target=drain_host_socket,
            args=(conn, len(guest_to_host), host_result),
            daemon=True,
        )
        host_reader.start()
        for offset in range(0, len(guest_to_host), TCP_CHUNK_BYTES):
            chunk = guest_to_host[offset:offset + TCP_CHUNK_BYTES]
            control.transact(
                proc,
                responses,
                control.OP_WRITE,
                control.request(control.OP_WRITE, guest_handle, data=chunk),
                {"length": len(chunk)},
            )
        host_reader.join(HOST_DRAIN_TIMEOUT)
        if host_reader.is_alive():
            raise TimeoutError(
                f"{cc_name}: host drain did not finish within {HOST_DRAIN_TIMEOUT:.0f}s"
            )
        if "error" in host_result:
            raise RuntimeError(f"{cc_name}: host drain failed") from host_result["error"]
        received = host_result.get("data")
        if received != guest_to_host:
            raise RuntimeError(f"{cc_name}: guest-to-host TCP payload mismatch")

        conn.sendall(host_to_guest)
        received_guest = bytearray()
        for offset in range(0, len(host_to_guest), TCP_CHUNK_BYTES):
            chunk = host_to_guest[offset:offset + TCP_CHUNK_BYTES]
            _, _, data = control.transact(
                proc,
                responses,
                control.OP_READ,
                control.request(control.OP_READ, guest_handle, len(chunk)),
                {"data": chunk},
            )
            received_guest.extend(data)
        if bytes(received_guest) != host_to_guest:
            raise RuntimeError(f"{cc_name}: host-to-guest TCP payload mismatch")

        tcp_info = query_tcp_info(proc, responses, guest_handle, cc_name)

        control.transact(
            proc,
            responses,
            control.OP_CLOSE,
            control.request(control.OP_CLOSE, guest_handle),
        )
        guest_handle = None
        return (
            f"{cc_name}: guest={GUEST_IPV4} host={HOST_IPV4}:{port} "
            f"guest_to_host={len(guest_to_host)} host_to_guest={len(host_to_guest)} "
            f"state={tcp_info['state']} ca_state={tcp_info['ca_state']} "
            f"rto_us={tcp_info['rto_us']} rtt_us={tcp_info['rtt_us']} "
            f"rttvar_us={tcp_info['rttvar_us']} snd_cwnd={tcp_info['snd_cwnd']} "
            f"snd_ssthresh={tcp_info['snd_ssthresh']} unacked={tcp_info['unacked']} "
            f"lost={tcp_info['lost']} retrans={tcp_info['retrans']} "
            f"total_retrans={tcp_info['total_retrans']} "
            f"pacing_rate={tcp_info['pacing_rate']} "
            f"max_pacing_rate={tcp_info['max_pacing_rate']} "
            f"delivery_rate={tcp_info['delivery_rate']}"
        )
    finally:
        if conn is not None:
            conn.close()
        listener.close()


def exercise_inbound_tcp_listener(proc: subprocess.Popen, responses: bytearray,
                                  cc_name: str, server_to_client_bytes: int,
                                  client_to_server_bytes: int) -> str:
    """Prove that a hosted listener and its accepted child use the requested CC."""
    port = INBOUND_TCP_PORTS[cc_name]
    listener_handle: int | None = None
    accepted_handle: int | None = None
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.settimeout(control.CONTROL_TIMEOUT)

    server_to_client = control.make_payload(
        f"tcpcc-tun-{cc_name}-server-to-client:".encode("ascii"),
        server_to_client_bytes,
    )
    client_to_server = control.make_payload(
        f"tcpcc-tun-{cc_name}-client-to-server:".encode("ascii"),
        client_to_server_bytes,
    )

    try:
        listener_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_SOCKET,
            control.request(control.OP_SOCKET),
        )
        if listener_handle <= 0:
            raise RuntimeError(
                f"listener-{cc_name}: invalid listener handle {listener_handle}"
            )

        control.transact(
            proc,
            responses,
            control.OP_SET_CC,
            control.request(
                control.OP_SET_CC,
                listener_handle,
                data=cc_name.encode("ascii"),
            ),
        )
        control.transact(
            proc,
            responses,
            control.OP_GET_CC,
            control.request(control.OP_GET_CC, listener_handle),
            {"data": cc_name.encode("ascii")},
        )
        control.transact(
            proc,
            responses,
            control.OP_BIND,
            control.request(
                control.OP_BIND,
                listener_handle,
                GUEST_IPV4_U32,
                port,
            ),
        )
        control.transact(
            proc,
            responses,
            control.OP_LISTEN,
            control.request(control.OP_LISTEN, listener_handle, 8),
        )

        # Bind the host-side client explicitly so this exercises the real TUN
        # path in the same direction as a future public ingress connection.
        client.bind((HOST_IPV4, 0))
        client.connect((GUEST_IPV4, port))
        client_port = client.getsockname()[1]

        accepted_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_ACCEPT,
            control.request(control.OP_ACCEPT, listener_handle),
        )
        if accepted_handle <= 0:
            raise RuntimeError(
                f"listener-{cc_name}: invalid accepted handle {accepted_handle}"
            )
        control.transact(
            proc,
            responses,
            control.OP_GET_CC,
            control.request(control.OP_GET_CC, accepted_handle),
            {"data": cc_name.encode("ascii")},
        )

        host_result: dict[str, object] = {}
        host_reader = threading.Thread(
            target=drain_host_socket,
            args=(client, len(server_to_client), host_result),
            daemon=True,
        )
        host_reader.start()
        for offset in range(0, len(server_to_client), TCP_CHUNK_BYTES):
            chunk = server_to_client[offset:offset + TCP_CHUNK_BYTES]
            control.transact(
                proc,
                responses,
                control.OP_WRITE,
                control.request(control.OP_WRITE, accepted_handle, data=chunk),
                {"length": len(chunk)},
            )
        host_reader.join(HOST_DRAIN_TIMEOUT)
        if host_reader.is_alive():
            raise TimeoutError(
                f"listener-{cc_name}: host drain did not finish within "
                f"{HOST_DRAIN_TIMEOUT:.0f}s"
            )
        if "error" in host_result:
            raise RuntimeError(
                f"listener-{cc_name}: host drain failed"
            ) from host_result["error"]
        if host_result.get("data") != server_to_client:
            raise RuntimeError(
                f"listener-{cc_name}: server-to-client TCP payload mismatch"
            )

        client.sendall(client_to_server)
        received_server = bytearray()
        for offset in range(0, len(client_to_server), TCP_CHUNK_BYTES):
            chunk = client_to_server[offset:offset + TCP_CHUNK_BYTES]
            _, _, data = control.transact(
                proc,
                responses,
                control.OP_READ,
                control.request(control.OP_READ, accepted_handle, len(chunk)),
                {"data": chunk},
            )
            received_server.extend(data)
        if bytes(received_server) != client_to_server:
            raise RuntimeError(
                f"listener-{cc_name}: client-to-server TCP payload mismatch"
            )

        tcp_info = query_tcp_info(
            proc,
            responses,
            accepted_handle,
            f"listener-{cc_name}",
        )

        control.transact(
            proc,
            responses,
            control.OP_CLOSE,
            control.request(control.OP_CLOSE, accepted_handle),
        )
        accepted_handle = None
        control.transact(
            proc,
            responses,
            control.OP_CLOSE,
            control.request(control.OP_CLOSE, listener_handle),
        )
        listener_handle = None
        return (
            f"listener-{cc_name}: guest={GUEST_IPV4}:{port} "
            f"host={HOST_IPV4}:{client_port} listener_cc={cc_name} "
            f"accepted_cc={cc_name} server_to_client={len(server_to_client)} "
            f"client_to_server={len(client_to_server)} state={tcp_info['state']} "
            f"ca_state={tcp_info['ca_state']} rto_us={tcp_info['rto_us']} "
            f"rtt_us={tcp_info['rtt_us']} rttvar_us={tcp_info['rttvar_us']} "
            f"snd_cwnd={tcp_info['snd_cwnd']} "
            f"snd_ssthresh={tcp_info['snd_ssthresh']} "
            f"unacked={tcp_info['unacked']} lost={tcp_info['lost']} "
            f"retrans={tcp_info['retrans']} "
            f"total_retrans={tcp_info['total_retrans']} "
            f"pacing_rate={tcp_info['pacing_rate']} "
            f"max_pacing_rate={tcp_info['max_pacing_rate']} "
            f"delivery_rate={tcp_info['delivery_rate']}"
        )
    finally:
        client.close()


def exercise_single_bridge(proc: subprocess.Popen,
                           responses: bytearray) -> str:
    """Bridge one public BBR child to a nonblocking host-loopback backend."""
    backend_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    backend_listener.settimeout(control.CONTROL_TIMEOUT)
    backend_listener.bind(("127.0.0.1", 0))
    backend_listener.listen(1)
    backend_port = backend_listener.getsockname()[1]

    payload = control.make_payload(
        b"tcpcc-m8.2.4-single-session-bridge:",
        BRIDGE_TRANSFER_BYTES,
    )
    backend_result: dict[str, object] = {}
    backend_thread = threading.Thread(
        target=bridge_backend_worker,
        args=(backend_listener, payload, backend_result),
        daemon=True,
    )
    backend_thread.start()

    listener_handle: int | None = None
    accepted_handle: int | None = None
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.settimeout(control.CONTROL_TIMEOUT)

    try:
        listener_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_SOCKET,
            control.request(control.OP_SOCKET),
        )
        if listener_handle <= 0:
            raise RuntimeError(
                f"bridge-bbr: invalid listener handle {listener_handle}"
            )

        control.transact(
            proc,
            responses,
            control.OP_SET_CC,
            control.request(
                control.OP_SET_CC,
                listener_handle,
                data=b"bbr",
            ),
        )
        control.transact(
            proc,
            responses,
            control.OP_GET_CC,
            control.request(control.OP_GET_CC, listener_handle),
            {"data": b"bbr"},
        )
        control.transact(
            proc,
            responses,
            control.OP_BIND,
            control.request(
                control.OP_BIND,
                listener_handle,
                GUEST_IPV4_U32,
                BRIDGE_TCP_PORT,
            ),
        )
        control.transact(
            proc,
            responses,
            control.OP_LISTEN,
            control.request(control.OP_LISTEN, listener_handle, 8),
        )

        client.bind((HOST_IPV4, 0))
        client.connect((GUEST_IPV4, BRIDGE_TCP_PORT))
        client_port = client.getsockname()[1]

        accepted_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_ACCEPT,
            control.request(control.OP_ACCEPT, listener_handle),
        )
        if accepted_handle <= 0:
            raise RuntimeError(
                f"bridge-bbr: invalid accepted handle {accepted_handle}"
            )
        control.transact(
            proc,
            responses,
            control.OP_GET_CC,
            control.request(control.OP_GET_CC, accepted_handle),
            {"data": b"bbr"},
        )

        bridge_control_offset = len(responses)
        start_request = control.request(
            control.OP_BRIDGE_START,
            accepted_handle,
            control.LOOPBACK,
            backend_port,
        )
        bridge_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_BRIDGE_START,
            start_request,
            {"length": 0},
        )
        decode_bridge_handle(bridge_handle, "bridge-bbr")
        accepted_handle = None

        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        echoed = recv_exact(client, len(payload))
        if echoed != payload:
            raise RuntimeError("bridge-bbr: backend-to-public payload mismatch")
        if client.recv(1):
            raise RuntimeError("bridge-bbr: public connection did not end at EOF")

        backend_thread.join(HOST_DRAIN_TIMEOUT)
        if backend_thread.is_alive():
            raise TimeoutError(
                "bridge-bbr: backend did not finish within "
                f"{HOST_DRAIN_TIMEOUT:.0f}s"
            )
        if "error" in backend_result:
            raise RuntimeError(
                "bridge-bbr: loopback backend failed"
            ) from backend_result["error"]
        if backend_result.get("data") != payload:
            raise RuntimeError("bridge-bbr: public-to-backend payload mismatch")

        join_request = control.request(
            control.OP_BRIDGE_JOIN,
            bridge_handle,
            BRIDGE_JOIN_TIMEOUT_MS,
        )
        _, length, raw_result = control.transact(
            proc,
            responses,
            control.OP_BRIDGE_JOIN,
            join_request,
            {"length": BRIDGE_RESULT.size},
        )
        if length != BRIDGE_RESULT.size:
            raise RuntimeError(
                f"bridge-bbr: result size {length} != {BRIDGE_RESULT.size}"
            )
        result = validate_bridge_result(
            bridge_handle,
            raw_result,
            payload,
            "bridge-bbr",
        )
        bridge_control_records = (
            start_request
            + join_request
            + bytes(responses[bridge_control_offset:])
        )
        if payload[:64] in bridge_control_records:
            raise RuntimeError("bridge-bbr: payload leaked into the control ABI")

        control.transact(
            proc,
            responses,
            control.OP_CLOSE,
            control.request(control.OP_CLOSE, listener_handle),
        )
        listener_handle = None
        return (
            f"bridge-bbr: guest={GUEST_IPV4}:{BRIDGE_TCP_PORT} "
            f"host={HOST_IPV4}:{client_port} "
            f"backend=127.0.0.1:{backend_port} listener_cc=bbr accepted_cc=bbr "
            f"handle={bridge_handle} slot={result['slot']} "
            f"generation={result['generation']} "
            f"public_to_backend={result['public_to_backend']} "
            f"backend_to_public={result['backend_to_public']} "
            f"buffer_limit={result['buffer_limit']} "
            f"total_buffer_limit={result['total_buffer_limit']} "
            f"session_limit={result['session_limit']} "
            f"send_eagain={result['host_send_eagain']} "
            f"data_plane_control_bytes=0 token=0x{result['token']:016x}"
        )
    finally:
        client.close()
        backend_listener.close()


def start_bridge_session(proc: subprocess.Popen, responses: bytearray,
                         label: str, cc_name: str, public_port: int,
                         payload: bytes,
                         release: threading.Event | None = None,
                         receive_buffer: int | None = None,
                         reset_backend: bool = False) -> dict[str, object]:
    backend_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    backend_listener.settimeout(HOST_DRAIN_TIMEOUT)
    backend_listener.bind(("127.0.0.1", 0))
    backend_listener.listen(1)
    backend_port = backend_listener.getsockname()[1]
    backend_result: dict[str, object] = {}
    backend_ready = threading.Event()
    backend_thread = threading.Thread(
        target=bridge_backend_worker,
        args=(
            backend_listener,
            payload,
            backend_result,
            backend_ready,
            release,
            receive_buffer,
            reset_backend,
        ),
        daemon=True,
    )
    backend_thread.start()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.settimeout(HOST_DRAIN_TIMEOUT)
    listener_handle: int | None = None
    accepted_handle: int | None = None

    try:
        listener_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_SOCKET,
            control.request(control.OP_SOCKET),
        )
        if listener_handle <= 0:
            raise RuntimeError(
                f"{label}: invalid listener handle {listener_handle}"
            )
        control.transact(
            proc,
            responses,
            control.OP_SET_CC,
            control.request(
                control.OP_SET_CC,
                listener_handle,
                data=cc_name.encode("ascii"),
            ),
        )
        control.transact(
            proc,
            responses,
            control.OP_GET_CC,
            control.request(control.OP_GET_CC, listener_handle),
            {"data": cc_name.encode("ascii")},
        )
        control.transact(
            proc,
            responses,
            control.OP_BIND,
            control.request(
                control.OP_BIND,
                listener_handle,
                GUEST_IPV4_U32,
                public_port,
            ),
        )
        control.transact(
            proc,
            responses,
            control.OP_LISTEN,
            control.request(control.OP_LISTEN, listener_handle, 8),
        )

        client.bind((HOST_IPV4, 0))
        client.connect((GUEST_IPV4, public_port))
        client_port = client.getsockname()[1]
        accepted_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_ACCEPT,
            control.request(control.OP_ACCEPT, listener_handle),
        )
        if accepted_handle <= 0:
            raise RuntimeError(
                f"{label}: invalid accepted handle {accepted_handle}"
            )
        control.transact(
            proc,
            responses,
            control.OP_GET_CC,
            control.request(control.OP_GET_CC, accepted_handle),
            {"data": cc_name.encode("ascii")},
        )

        control_offset = len(responses)
        start_request = control.request(
            control.OP_BRIDGE_START,
            accepted_handle,
            control.LOOPBACK,
            backend_port,
        )
        bridge_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_BRIDGE_START,
            start_request,
            {"length": 0},
        )
        decode_bridge_handle(bridge_handle, label)
        accepted_handle = None

        control.transact(
            proc,
            responses,
            control.OP_CLOSE,
            control.request(control.OP_CLOSE, listener_handle),
        )
        listener_handle = None
        if not backend_ready.wait(control.CONTROL_TIMEOUT):
            raise TimeoutError(f"{label}: backend accept did not become ready")
        if "error" in backend_result:
            raise RuntimeError(
                f"{label}: backend failed during accept"
            ) from backend_result["error"]

        return {
            "label": label,
            "cc_name": cc_name,
            "public_port": public_port,
            "payload": payload,
            "backend_listener": backend_listener,
            "backend_port": backend_port,
            "backend_result": backend_result,
            "backend_thread": backend_thread,
            "backend_release": release,
            "client": client,
            "client_port": client_port,
            "bridge_handle": bridge_handle,
            "control_offset": control_offset,
            "start_request": start_request,
        }
    except Exception:
        if release is not None:
            release.set()
        client.close()
        backend_listener.close()
        raise


def bridge_client_worker(session: dict[str, object],
                         done: threading.Event) -> None:
    client = session["client"]
    payload = session["payload"]
    result: dict[str, object] = {}
    session["client_result"] = result
    try:
        assert isinstance(client, socket.socket)
        assert isinstance(payload, bytes)
        result["stage"] = "send"
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        result["stage"] = "receive"
        echoed = recv_exact(client, len(payload))
        if echoed != payload:
            raise RuntimeError("backend-to-public payload mismatch")
        if client.recv(1):
            raise RuntimeError("public connection did not end at EOF")
        result["data"] = echoed
        result["stage"] = "complete"
    except Exception as exc:
        result["error"] = exc
    finally:
        done.set()


def start_bridge_client(session: dict[str, object]) -> None:
    done = threading.Event()
    thread = threading.Thread(
        target=bridge_client_worker,
        args=(session, done),
        daemon=True,
    )
    session["client_done"] = done
    session["client_thread"] = thread
    thread.start()


def wait_bridge_client(session: dict[str, object], timeout: float) -> None:
    label = str(session["label"])
    done = session["client_done"]
    assert isinstance(done, threading.Event)
    if not done.wait(timeout):
        raise TimeoutError(f"{label}: public client timed out after {timeout:.0f}s")
    result = session.get("client_result")
    if not isinstance(result, dict):
        raise RuntimeError(f"{label}: public client produced no result")
    if "error" in result:
        backend_result = session.get("backend_result")
        backend_stage = None
        if isinstance(backend_result, dict):
            backend_stage = (
                f"{backend_result.get('stage')}/"
                f"{backend_result.get('received_bytes', 0)}"
            )
        raise RuntimeError(
            f"{label}: public client failed during {result.get('stage')}: "
            f"{result['error']} (backend stage={backend_stage})"
        ) from result["error"]
    if result.get("data") != session["payload"]:
        raise RuntimeError(f"{label}: public client payload mismatch")


def finish_bridge_session(
    proc: subprocess.Popen,
    responses: bytearray,
    session: dict[str, object],
) -> tuple[dict[str, int], str]:
    label = str(session["label"])
    payload = session["payload"]
    backend_thread = session["backend_thread"]
    assert isinstance(payload, bytes)
    assert isinstance(backend_thread, threading.Thread)
    wait_bridge_client(session, HOST_DRAIN_TIMEOUT)
    backend_thread.join(HOST_DRAIN_TIMEOUT)
    if backend_thread.is_alive():
        raise TimeoutError(f"{label}: backend did not finish")
    backend_result = session["backend_result"]
    assert isinstance(backend_result, dict)
    if "error" in backend_result:
        raise RuntimeError(f"{label}: loopback backend failed") from backend_result[
            "error"
        ]
    if backend_result.get("data") != payload:
        raise RuntimeError(f"{label}: public-to-backend payload mismatch")

    bridge_handle = int(session["bridge_handle"])
    join_request = control.request(
        control.OP_BRIDGE_JOIN,
        bridge_handle,
        BRIDGE_JOIN_TIMEOUT_MS,
    )
    _, length, raw_result = control.transact(
        proc,
        responses,
        control.OP_BRIDGE_JOIN,
        join_request,
        {"length": BRIDGE_RESULT.size},
    )
    if length != BRIDGE_RESULT.size:
        raise RuntimeError(
            f"{label}: bridge result size {length} != {BRIDGE_RESULT.size}"
        )
    result = validate_bridge_result(
        bridge_handle,
        raw_result,
        payload,
        label,
    )
    start_request = session["start_request"]
    assert isinstance(start_request, bytes)
    control_offset = int(session["control_offset"])
    control_records = (
        start_request + join_request + bytes(responses[control_offset:])
    )
    if payload[:64] in control_records:
        raise RuntimeError(f"{label}: payload leaked into the control ABI")

    client = session["client"]
    assert isinstance(client, socket.socket)
    client.close()
    log = (
        f"{label}: guest={GUEST_IPV4}:{session['public_port']} "
        f"host={HOST_IPV4}:{session['client_port']} "
        f"backend=127.0.0.1:{session['backend_port']} "
        f"listener_cc={session['cc_name']} accepted_cc={session['cc_name']} "
        f"handle={bridge_handle} slot={result['slot']} "
        f"generation={result['generation']} "
        f"public_to_backend={result['public_to_backend']} "
        f"backend_to_public={result['backend_to_public']} "
        f"send_eagain={result['host_send_eagain']} "
        f"partial_writes={result['host_partial_writes']} "
        f"recv_eagain={result['host_recv_eagain']} "
        f"buffer_limit={result['buffer_limit']} "
        f"total_buffer_limit={result['total_buffer_limit']} "
        f"session_limit={result['session_limit']} "
        f"data_plane_control_bytes=0 token=0x{result['token']:016x}"
    )
    return result, log


def wait_cancelled_bridge_threads(
    session: dict[str, object],
) -> tuple[str, str]:
    label = str(session["label"])
    done = session["client_done"]
    release = session["backend_release"]
    backend_thread = session["backend_thread"]
    assert isinstance(done, threading.Event)
    assert isinstance(release, threading.Event)
    assert isinstance(backend_thread, threading.Thread)

    if not done.wait(HOST_DRAIN_TIMEOUT):
        raise TimeoutError(f"{label}: canceled public client did not terminate")
    client_result = session.get("client_result")
    if not isinstance(client_result, dict) or "error" not in client_result:
        raise RuntimeError(
            f"{label}: canceled public client unexpectedly completed normally"
        )

    release.set()
    backend_thread.join(HOST_DRAIN_TIMEOUT)
    if backend_thread.is_alive():
        raise TimeoutError(f"{label}: canceled backend did not terminate")
    backend_result = session["backend_result"]
    assert isinstance(backend_result, dict)
    if "error" not in backend_result:
        raise RuntimeError(
            f"{label}: canceled backend unexpectedly completed normally"
        )

    client = session["client"]
    assert isinstance(client, socket.socket)
    client.close()
    return (
        type(client_result["error"]).__name__,
        type(backend_result["error"]).__name__,
    )


def cancel_and_reap_bridge_session(
    proc: subprocess.Popen,
    responses: bytearray,
    session: dict[str, object],
) -> tuple[dict[str, int], str]:
    label = str(session["label"])
    payload = session["payload"]
    assert isinstance(payload, bytes)
    bridge_handle = int(session["bridge_handle"])
    slot, generation = decode_bridge_handle(bridge_handle, label)
    cancel_request = control.request(control.OP_BRIDGE_CANCEL, bridge_handle)
    control.transact(
        proc,
        responses,
        control.OP_BRIDGE_CANCEL,
        cancel_request,
        {"length": 0},
    )
    client_error, backend_error = wait_cancelled_bridge_threads(session)

    join_request = control.request(
        control.OP_BRIDGE_JOIN,
        bridge_handle,
        BRIDGE_JOIN_TIMEOUT_MS,
    )
    control.transact(
        proc,
        responses,
        control.OP_BRIDGE_JOIN,
        join_request,
        {"status": -errno.ECANCELED, "length": 0},
    )

    start_request = session["start_request"]
    assert isinstance(start_request, bytes)
    control_offset = int(session["control_offset"])
    control_records = (
        start_request
        + cancel_request
        + join_request
        + bytes(responses[control_offset:])
    )
    if payload[:64] in control_records:
        raise RuntimeError(f"{label}: payload leaked into the control ABI")

    result = {
        "handle": bridge_handle,
        "slot": slot,
        "generation": generation,
    }
    log = (
        f"{label}: guest={GUEST_IPV4}:{session['public_port']} "
        f"backend=127.0.0.1:{session['backend_port']} "
        f"handle={bridge_handle} slot={slot} generation={generation} "
        f"cancel_status=0 join_status={-errno.ECANCELED} "
        f"client_error={client_error} backend_error={backend_error} "
        "data_plane_control_bytes=0"
    )
    return result, log


def exercise_concurrent_bridges(proc: subprocess.Popen,
                                responses: bytearray) -> list[str]:
    delayed_release = threading.Event()
    sessions: list[dict[str, object]] = []
    logs: list[str] = []
    try:
        fast = start_bridge_session(
            proc,
            responses,
            "bridge-fast-cubic",
            "cubic",
            BRIDGE_CONCURRENT_PORTS["fast-cubic"],
            control.make_payload(
                b"tcpcc-m8.2.5-concurrent-fast-cubic:",
                BRIDGE_FAST_BYTES,
            ),
        )
        sessions.append(fast)
        delayed = start_bridge_session(
            proc,
            responses,
            "bridge-delayed-bbr",
            "bbr",
            BRIDGE_CONCURRENT_PORTS["delayed-bbr"],
            control.make_payload(
                b"tcpcc-m8.2.5-concurrent-delayed-bbr:",
                BRIDGE_DELAYED_BYTES,
            ),
            release=delayed_release,
            receive_buffer=4096,
        )
        sessions.append(delayed)

        start_bridge_client(delayed)
        start_bridge_client(fast)
        wait_bridge_client(fast, 15.0)
        delayed_done = delayed["client_done"]
        assert isinstance(delayed_done, threading.Event)
        if delayed_done.is_set():
            raise RuntimeError(
                "bridge-delayed-bbr: completed before backend release"
            )

        fast_result, fast_log = finish_bridge_session(proc, responses, fast)
        logs.append(fast_log)

        reuse = start_bridge_session(
            proc,
            responses,
            "bridge-reuse-cubic",
            "cubic",
            BRIDGE_CONCURRENT_PORTS["reuse-cubic"],
            control.make_payload(
                b"tcpcc-m8.2.5-reused-slot-cubic:",
                BRIDGE_REUSE_BYTES,
            ),
        )
        sessions.append(reuse)
        old_slot, old_generation = decode_bridge_handle(
            int(fast["bridge_handle"]), "bridge-fast-cubic"
        )
        new_slot, new_generation = decode_bridge_handle(
            int(reuse["bridge_handle"]), "bridge-reuse-cubic"
        )
        if new_slot != old_slot or new_generation == old_generation:
            raise RuntimeError(
                "bridge-reuse-cubic: released slot was not reused with a new "
                f"generation (old={old_slot}/{old_generation}, "
                f"new={new_slot}/{new_generation})"
            )
        control.transact(
            proc,
            responses,
            control.OP_BRIDGE_JOIN,
            control.request(
                control.OP_BRIDGE_JOIN,
                int(fast["bridge_handle"]),
                1,
            ),
            {"status": -errno.ENOENT},
        )

        start_bridge_client(reuse)
        wait_bridge_client(reuse, 15.0)
        reuse_result, reuse_log = finish_bridge_session(proc, responses, reuse)
        logs.append(reuse_log)
        if delayed_done.is_set():
            raise RuntimeError(
                "bridge-delayed-bbr: completed while its backend remained blocked"
            )

        delayed_release.set()
        wait_bridge_client(delayed, HOST_DRAIN_TIMEOUT)
        delayed_result, delayed_log = finish_bridge_session(
            proc,
            responses,
            delayed,
        )
        logs.append(delayed_log)
        logs.append(
            "bridge-concurrency: "
            f"fast_handle={fast['bridge_handle']} "
            f"delayed_handle={delayed['bridge_handle']} "
            f"reused_handle={reuse['bridge_handle']} "
            f"reused_slot={new_slot} old_generation={old_generation} "
            f"new_generation={new_generation} stale_handle_status={-errno.ENOENT} "
            "release_barrier=passed "
            f"delayed_send_eagain={delayed_result['host_send_eagain']} "
            f"fast_bytes={fast_result['public_to_backend']} "
            f"reuse_bytes={reuse_result['public_to_backend']} "
            f"delayed_bytes={delayed_result['public_to_backend']} "
            f"total_buffer_limit={delayed_result['total_buffer_limit']} "
            f"session_limit={delayed_result['session_limit']}"
        )
        return logs
    finally:
        delayed_release.set()
        for session in sessions:
            client = session.get("client")
            if isinstance(client, socket.socket):
                client.close()
            listener = session.get("backend_listener")
            if isinstance(listener, socket.socket):
                listener.close()


def reject_bridge_over_capacity(
    proc: subprocess.Popen,
    responses: bytearray,
) -> None:
    backend_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    backend_listener.bind(("127.0.0.1", 0))
    backend_listener.listen(1)
    backend_port = backend_listener.getsockname()[1]
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(HOST_DRAIN_TIMEOUT)
    listener_handle: int | None = None
    accepted_handle: int | None = None
    try:
        listener_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_SOCKET,
            control.request(control.OP_SOCKET),
        )
        control.transact(
            proc,
            responses,
            control.OP_SET_CC,
            control.request(
                control.OP_SET_CC,
                listener_handle,
                data=b"cubic",
            ),
        )
        control.transact(
            proc,
            responses,
            control.OP_BIND,
            control.request(
                control.OP_BIND,
                listener_handle,
                GUEST_IPV4_U32,
                BRIDGE_CAPACITY_OVERFLOW_PORT,
            ),
        )
        control.transact(
            proc,
            responses,
            control.OP_LISTEN,
            control.request(control.OP_LISTEN, listener_handle, 1),
        )
        client.bind((HOST_IPV4, 0))
        client.connect((GUEST_IPV4, BRIDGE_CAPACITY_OVERFLOW_PORT))
        accepted_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_ACCEPT,
            control.request(control.OP_ACCEPT, listener_handle),
        )
        control.transact(
            proc,
            responses,
            control.OP_BRIDGE_START,
            control.request(
                control.OP_BRIDGE_START,
                accepted_handle,
                control.LOOPBACK,
                backend_port,
            ),
            {"status": -errno.ENOSPC, "length": 0},
        )
    finally:
        for handle in (accepted_handle, listener_handle):
            if handle is None:
                continue
            try:
                control.transact(
                    proc,
                    responses,
                    control.OP_CLOSE,
                    control.request(control.OP_CLOSE, handle),
                )
            except Exception:
                pass
        client.close()
        backend_listener.close()


def exercise_bridge_capacity(
    proc: subprocess.Popen,
    responses: bytearray,
) -> list[str]:
    release = threading.Event()
    sessions: list[dict[str, object]] = []
    logs: list[str] = []
    try:
        for index in range(BRIDGE_SESSION_LIMIT):
            session = start_bridge_session(
                proc,
                responses,
                f"bridge-capacity-{index}",
                "bbr" if index & 1 else "cubic",
                BRIDGE_CAPACITY_PORT_BASE + index,
                control.make_payload(
                    f"tcpcc-m8.5-capacity-{index}:".encode("ascii"),
                    BRIDGE_CAPACITY_BYTES + index,
                ),
                release=release,
                receive_buffer=4096,
            )
            sessions.append(session)

        slots = {
            decode_bridge_handle(
                int(session["bridge_handle"]),
                str(session["label"]),
            )[0]
            for session in sessions
        }
        if len(slots) != BRIDGE_SESSION_LIMIT:
            raise RuntimeError(
                f"bridge capacity allocated only {len(slots)} unique slots"
            )
        reject_bridge_over_capacity(proc, responses)

        for session in sessions:
            start_bridge_client(session)
        release.set()
        for session in sessions:
            _result, log = finish_bridge_session(proc, responses, session)
            logs.append(log)

        replacement = start_bridge_session(
            proc,
            responses,
            "bridge-capacity-replacement",
            "bbr",
            BRIDGE_CAPACITY_REPLACEMENT_PORT,
            control.make_payload(
                b"tcpcc-m8.5-capacity-replacement:",
                BRIDGE_CAPACITY_BYTES,
            ),
        )
        sessions.append(replacement)
        start_bridge_client(replacement)
        replacement_result, replacement_log = finish_bridge_session(
            proc,
            responses,
            replacement,
        )
        logs.append(replacement_log)
        logs.append(
            "bridge-capacity: "
            f"active_limit={BRIDGE_SESSION_LIMIT} "
            f"unique_slots={len(slots)} overflow_status={-errno.ENOSPC} "
            f"replacement_handle={replacement['bridge_handle']} "
            f"replacement_bytes={replacement_result['public_to_backend']} "
            "slot_recovery=passed"
        )
        return logs
    finally:
        release.set()
        for session in sessions:
            client = session.get("client")
            if isinstance(client, socket.socket):
                client.close()
            listener = session.get("backend_listener")
            if isinstance(listener, socket.socket):
                listener.close()


def exercise_reset_isolation(
    proc: subprocess.Popen,
    responses: bytearray,
) -> list[str]:
    survivor_release = threading.Event()
    sessions: list[dict[str, object]] = []
    logs: list[str] = []
    try:
        survivor = start_bridge_session(
            proc,
            responses,
            "bridge-reset-survivor-cubic",
            "cubic",
            BRIDGE_RESET_PORTS["survivor-cubic"],
            control.make_payload(
                b"tcpcc-m8.5-reset-survivor-cubic:",
                BRIDGE_RESET_SURVIVOR_BYTES,
            ),
            release=survivor_release,
            receive_buffer=4096,
        )
        sessions.append(survivor)
        start_bridge_client(survivor)

        backend_reset = start_bridge_session(
            proc,
            responses,
            "bridge-reset-backend-bbr",
            "bbr",
            BRIDGE_RESET_PORTS["backend-bbr"],
            b"",
            reset_backend=True,
        )
        sessions.append(backend_reset)
        backend_client = backend_reset["client"]
        assert isinstance(backend_client, socket.socket)
        try:
            backend_signal = (
                "eof" if backend_client.recv(1) == b"" else "unexpected-data"
            )
        except OSError as error:
            backend_signal = type(error).__name__
        backend_result = join_terminal_bridge(proc, responses, backend_reset)
        if not backend_result["terminal_events"] & control.HOST_EVENT_ERROR:
            raise RuntimeError(
                "bridge-reset-backend-bbr: host reset omitted ERROR event"
            )
        backend_thread = backend_reset["backend_thread"]
        assert isinstance(backend_thread, threading.Thread)
        backend_thread.join(HOST_DRAIN_TIMEOUT)
        if backend_thread.is_alive():
            raise TimeoutError("backend-reset worker did not finish")

        public_reset = start_bridge_session(
            proc,
            responses,
            "bridge-reset-public-bbr",
            "bbr",
            BRIDGE_RESET_PORTS["public-bbr"],
            control.make_payload(
                b"tcpcc-m8.5-reset-public-bbr:",
                BRIDGE_PUBLIC_RESET_BYTES,
            ),
        )
        sessions.append(public_reset)
        public_client = public_reset["client"]
        public_payload = public_reset["payload"]
        assert isinstance(public_client, socket.socket)
        assert isinstance(public_payload, bytes)
        public_client.sendall(public_payload)
        public_client.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_LINGER,
            struct.pack("ii", 1, 0),
        )
        public_client.close()
        public_reset["client"] = None
        public_result = join_terminal_bridge(proc, responses, public_reset)
        public_thread = public_reset["backend_thread"]
        assert isinstance(public_thread, threading.Thread)
        public_thread.join(HOST_DRAIN_TIMEOUT)
        if public_thread.is_alive():
            raise TimeoutError("public-reset backend worker did not finish")

        survivor_done = survivor["client_done"]
        assert isinstance(survivor_done, threading.Event)
        if survivor_done.is_set():
            raise RuntimeError(
                "bridge-reset-survivor-cubic: reset leaked into survivor"
            )
        survivor_release.set()
        survivor_result, survivor_log = finish_bridge_session(
            proc,
            responses,
            survivor,
        )
        logs.append(survivor_log)
        logs.append(
            "bridge-reset-isolation: "
            f"backend_status={backend_result['status']} "
            f"backend_events=0x{backend_result['terminal_events']:x} "
            f"backend_client_signal={backend_signal} "
            f"public_status={public_result['status']} "
            f"public_events=0x{public_result['terminal_events']:x} "
            f"survivor_bytes={survivor_result['public_to_backend']} "
            "survivor_isolation=passed"
        )
        return logs
    finally:
        survivor_release.set()
        for session in sessions:
            client = session.get("client")
            if isinstance(client, socket.socket):
                client.close()
            listener = session.get("backend_listener")
            if isinstance(listener, socket.socket):
                listener.close()


def exercise_cancelled_bridges(proc: subprocess.Popen,
                               responses: bytearray) -> list[str]:
    victim_release = threading.Event()
    survivor_release = threading.Event()
    sessions: list[dict[str, object]] = []
    logs: list[str] = []
    try:
        victim = start_bridge_session(
            proc,
            responses,
            "bridge-cancel-victim-bbr",
            "bbr",
            BRIDGE_CANCEL_PORTS["victim-bbr"],
            control.make_payload(
                b"tcpcc-m8.2.6-cancel-victim-bbr:",
                BRIDGE_CANCEL_VICTIM_BYTES,
            ),
            release=victim_release,
            receive_buffer=4096,
        )
        sessions.append(victim)
        survivor = start_bridge_session(
            proc,
            responses,
            "bridge-cancel-survivor-cubic",
            "cubic",
            BRIDGE_CANCEL_PORTS["survivor-cubic"],
            control.make_payload(
                b"tcpcc-m8.2.6-cancel-survivor-cubic:",
                BRIDGE_CANCEL_SURVIVOR_BYTES,
            ),
            release=survivor_release,
        )
        sessions.append(survivor)

        start_bridge_client(victim)
        start_bridge_client(survivor)
        victim_result, victim_log = cancel_and_reap_bridge_session(
            proc,
            responses,
            victim,
        )
        logs.append(victim_log)
        survivor_done = survivor["client_done"]
        assert isinstance(survivor_done, threading.Event)
        if survivor_done.is_set():
            raise RuntimeError(
                "bridge-cancel-survivor-cubic: terminated with victim"
            )

        replacement = start_bridge_session(
            proc,
            responses,
            "bridge-cancel-replacement-cubic",
            "cubic",
            BRIDGE_CANCEL_PORTS["replacement-cubic"],
            control.make_payload(
                b"tcpcc-m8.2.6-cancel-replacement-cubic:",
                BRIDGE_CANCEL_REPLACEMENT_BYTES,
            ),
        )
        sessions.append(replacement)
        replacement_slot, replacement_generation = decode_bridge_handle(
            int(replacement["bridge_handle"]),
            "bridge-cancel-replacement-cubic",
        )
        if (
            replacement_slot != victim_result["slot"]
            or replacement_generation == victim_result["generation"]
        ):
            raise RuntimeError(
                "bridge-cancel-replacement-cubic: canceled slot was not reused "
                "with a new generation"
            )

        stale_handle = victim_result["handle"]
        control.transact(
            proc,
            responses,
            control.OP_BRIDGE_CANCEL,
            control.request(control.OP_BRIDGE_CANCEL, stale_handle),
            {"status": -errno.ENOENT, "length": 0},
        )
        control.transact(
            proc,
            responses,
            control.OP_BRIDGE_JOIN,
            control.request(control.OP_BRIDGE_JOIN, stale_handle, 1),
            {"status": -errno.ENOENT, "length": 0},
        )

        start_bridge_client(replacement)
        replacement_result, replacement_log = finish_bridge_session(
            proc,
            responses,
            replacement,
        )
        logs.append(replacement_log)
        if survivor_done.is_set():
            raise RuntimeError(
                "bridge-cancel-survivor-cubic: completed before release"
            )

        survivor_release.set()
        survivor_result, survivor_log = finish_bridge_session(
            proc,
            responses,
            survivor,
        )
        logs.append(survivor_log)
        logs.append(
            "bridge-cancellation: "
            f"victim_handle={stale_handle} "
            f"replacement_handle={replacement['bridge_handle']} "
            f"reused_slot={replacement_slot} "
            f"old_generation={victim_result['generation']} "
            f"new_generation={replacement_generation} "
            f"cancel_status=0 join_status={-errno.ECANCELED} "
            f"stale_status={-errno.ENOENT} survivor_release=passed "
            f"survivor_bytes={survivor_result['public_to_backend']} "
            f"replacement_bytes={replacement_result['public_to_backend']}"
        )
        return logs
    finally:
        victim_release.set()
        survivor_release.set()
        for session in sessions:
            client = session.get("client")
            if isinstance(client, socket.socket):
                client.close()
            listener = session.get("backend_listener")
            if isinstance(listener, socket.socket):
                listener.close()


def decode_service_stats(raw: bytes, expected_state: int) -> tuple[int, ...]:
    if len(raw) != SERVICE_STATS.size:
        raise RuntimeError(
            f"hosted service stats are {len(raw)} bytes, "
            f"expected {SERVICE_STATS.size}"
        )
    values = SERVICE_STATS.unpack(raw)
    if values[12] != expected_state:
        raise RuntimeError(
            f"hosted service state is {values[12]}, expected {expected_state}"
        )
    if values[13] > 0 or any(values[-3:]):
        raise RuntimeError(
            "hosted service stats contain invalid error/reserved fields: "
            f"last_error={values[13]} reserved={values[-3:]}"
        )
    return values


def exercise_hosted_service(proc: subprocess.Popen,
                            responses: bytearray) -> str:
    payload = control.make_payload(
        b"tcpcc-m9.2-hosted-service:",
        BRIDGE_TRANSFER_BYTES,
    )
    backend_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    backend_listener.settimeout(HOST_DRAIN_TIMEOUT)
    backend_listener.bind(("127.0.0.1", 0))
    backend_listener.listen(1)
    backend_port = backend_listener.getsockname()[1]
    backend_result: dict[str, object] = {}
    backend_ready = threading.Event()
    backend_thread = threading.Thread(
        target=bridge_backend_worker,
        args=(backend_listener, payload, backend_result, backend_ready),
        daemon=True,
    )
    backend_thread.start()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(HOST_DRAIN_TIMEOUT)
    listener_handle: int | None = None
    service_handle: int | None = None
    try:
        listener_handle, _, _ = control.transact(
            proc,
            responses,
            control.OP_SOCKET,
            control.request(control.OP_SOCKET),
        )
        control.transact(
            proc,
            responses,
            control.OP_SET_CC,
            control.request(control.OP_SET_CC, listener_handle, data=b"bbr"),
        )
        control.transact(
            proc,
            responses,
            control.OP_BIND,
            control.request(
                control.OP_BIND,
                listener_handle,
                GUEST_IPV4_U32,
                HOSTED_SERVICE_PORT,
            ),
        )
        control.transact(
            proc,
            responses,
            control.OP_LISTEN,
            control.request(control.OP_LISTEN, listener_handle, 8),
        )
        config = SERVICE_CONFIG.pack(control.LOOPBACK, backend_port, 0, 2, 4)
        service_handle, _, _ = control.transact(
            proc,
            responses,
            OP_SERVICE_START,
            control.request(
                OP_SERVICE_START,
                listener_handle,
                data=config,
            ),
            {"handle": 1, "length": 0},
        )
        listener_handle = None

        client.bind((HOST_IPV4, 0))
        client.connect((GUEST_IPV4, HOSTED_SERVICE_PORT))
        if not backend_ready.wait(control.CONTROL_TIMEOUT):
            raise TimeoutError("hosted service backend accept did not become ready")
        if "error" in backend_result:
            raise RuntimeError("hosted service backend accept failed") from backend_result[
                "error"
            ]
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        echoed = recv_exact(client, len(payload))
        if echoed != payload or client.recv(1):
            raise RuntimeError("hosted service payload or EOF mismatch")

        backend_thread.join(HOST_DRAIN_TIMEOUT)
        if backend_thread.is_alive():
            raise TimeoutError("hosted service backend did not finish")
        if "error" in backend_result:
            raise RuntimeError("hosted service backend failed") from backend_result[
                "error"
            ]

        _, _, raw_stats = control.transact(
            proc,
            responses,
            OP_SERVICE_DRAIN,
            control.request(OP_SERVICE_DRAIN, service_handle, 5000),
            {"length": SERVICE_STATS.size},
        )
        drain_stats = decode_service_stats(raw_stats, SERVICE_DRAINING)
        _, _, raw_stats = control.transact(
            proc,
            responses,
            OP_SERVICE_STATS,
            control.request(OP_SERVICE_STATS, service_handle),
            {"length": SERVICE_STATS.size},
        )
        observed_stats = decode_service_stats(raw_stats, SERVICE_DRAINING)
        if observed_stats != drain_stats:
            raise RuntimeError("hosted service stats changed after completed drain")

        _, _, raw_stats = control.transact(
            proc,
            responses,
            OP_SERVICE_STOP,
            control.request(OP_SERVICE_STOP, service_handle, 5000),
            {"length": SERVICE_STATS.size},
        )
        stop_stats = decode_service_stats(raw_stats, SERVICE_STOPPED)
        service_handle = None

        (accepted, completed, rejected, public_to_backend,
         backend_to_public, active, peak, maximum, accept_batch,
         _accept_eagain, bridge_failures, terminal_failures,
         _state, last_error, *_reserved) = stop_stats
        if (
            accepted != 1
            or completed != 1
            or rejected
            or public_to_backend != len(payload)
            or backend_to_public != len(payload)
            or active
            or peak != 1
            or maximum != 2
            or accept_batch != 4
            or bridge_failures
            or terminal_failures
            or last_error
        ):
            raise RuntimeError(f"unexpected hosted service stats {stop_stats}")
        return (
            "hosted-service-bbr: event_accept=passed event_reap=passed "
            f"accepted={accepted} completed={completed} active={active} "
            f"peak={peak} public_to_backend={public_to_backend} "
            f"backend_to_public={backend_to_public} state={SERVICE_STOPPED}"
        )
    finally:
        client.close()
        if service_handle is not None:
            try:
                control.transact(
                    proc,
                    responses,
                    OP_SERVICE_STOP,
                    control.request(OP_SERVICE_STOP, service_handle, 5000),
                )
            except Exception:
                pass
        if listener_handle is not None:
            try:
                control.transact(
                    proc,
                    responses,
                    control.OP_CLOSE,
                    control.request(control.OP_CLOSE, listener_handle),
                )
            except Exception:
                pass
        backend_listener.close()


def validate_global_cancelled_bridge(session: dict[str, object],
                                     responses: bytearray) -> str:
    label = str(session["label"])
    payload = session["payload"]
    assert isinstance(payload, bytes)
    client_error, backend_error = wait_cancelled_bridge_threads(session)
    control_offset = int(session["control_offset"])
    if payload[:64] in bytes(responses[control_offset:]):
        raise RuntimeError(f"{label}: payload leaked into the control ABI")
    handle = int(session["bridge_handle"])
    slot, generation = decode_bridge_handle(handle, label)
    return (
        f"{label}: guest={GUEST_IPV4}:{session['public_port']} "
        f"backend=127.0.0.1:{session['backend_port']} "
        f"handle={handle} slot={slot} generation={generation} "
        f"client_error={client_error} backend_error={backend_error} "
        "global_teardown=passed data_plane_control_bytes=0"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--tun-name", required=True)
    parser.add_argument("--boot-log", required=True, type=Path)
    parser.add_argument("--responses", required=True, type=Path)
    parser.add_argument("--ping-log", required=True, type=Path)
    parser.add_argument("--tcp-log", required=True, type=Path)
    parser.add_argument(
        "--guest-to-host-bytes", type=int, default=DEFAULT_TCP_TRANSFER_BYTES,
        help="bytes sent by each hosted CUBIC/BBR flow toward the host",
    )
    parser.add_argument(
        "--host-to-guest-bytes", type=int, default=DEFAULT_TCP_TRANSFER_BYTES,
        help="bytes returned by the host on each CUBIC/BBR connection",
    )
    parser.add_argument(
        "--exercise-listeners",
        action="store_true",
        help="also accept host-originated TCP on hosted CUBIC/BBR listeners",
    )
    args = parser.parse_args()

    if args.guest_to_host_bytes <= 0 or args.host_to_guest_bytes <= 0:
        parser.error("TCP transfer sizes must be positive")

    tun_fd = attach_tun_queue(args.tun_name)
    responses = bytearray()
    ping_log: list[str] = []
    tcp_log: list[str] = []
    proc: subprocess.Popen | None = None
    error: Exception | None = None
    stats: tuple[int, ...] | None = None
    finish_cancel_session: dict[str, object] | None = None

    try:
        proc = subprocess.Popen(
            [str(args.kernel)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(tun_fd,),
        )
        child_fd = tun_fd
        os.close(tun_fd)
        tun_fd = -1

        ifindex, _, _ = control.transact(
            proc,
            responses,
            control.OP_L3_ATTACH,
            control.request(
                control.OP_L3_ATTACH,
                child_fd,
                GUEST_IPV4_U32,
                GUEST_PREFIX,
            ),
        )
        if ifindex <= 0:
            raise RuntimeError(f"L3 attach returned invalid ifindex {ifindex}")

        append_command(
            ping_log,
            ping_command(args.tun_name, SMALL_PING_COUNT, SMALL_PING_PAYLOAD),
            expect_success=True,
        )
        append_command(
            ping_log,
            ping_command(args.tun_name, 1, MTU_PING_PAYLOAD, df=True),
            expect_success=True,
        )

        for cc_name in ("cubic", "bbr"):
            tcp_log.append(
                exercise_external_tcp(
                    proc,
                    responses,
                    cc_name,
                    args.guest_to_host_bytes,
                    args.host_to_guest_bytes,
                )
            )

        if args.exercise_listeners:
            for cc_name in ("cubic", "bbr"):
                tcp_log.append(
                    exercise_inbound_tcp_listener(
                        proc,
                        responses,
                        cc_name,
                        args.guest_to_host_bytes,
                        args.host_to_guest_bytes,
                    )
                )
            tcp_log.append(exercise_single_bridge(proc, responses))
            tcp_log.extend(exercise_concurrent_bridges(proc, responses))
            tcp_log.extend(exercise_bridge_capacity(proc, responses))
            tcp_log.extend(exercise_reset_isolation(proc, responses))
            tcp_log.extend(exercise_cancelled_bridges(proc, responses))
            tcp_log.append(exercise_hosted_service(proc, responses))

        # Temporarily let the host emit one 1501-byte IPv4 packet. The hosted
        # tcpcc0 MTU remains 1500, so M5.1 ingress validation must drop it.
        append_command(
            ping_log,
            ["sudo", "-n", "ip", "link", "set", "dev", args.tun_name,
             "mtu", "1501"],
            expect_success=True,
        )
        try:
            oversize_rc = append_command(
                ping_log,
                ping_command(args.tun_name, 1, OVERSIZE_PING_PAYLOAD, df=True),
                expect_success=False,
            )
        finally:
            append_command(
                ping_log,
                ["sudo", "-n", "ip", "link", "set", "dev", args.tun_name,
                 "mtu", "1500"],
                expect_success=True,
            )
        if oversize_rc == 0:
            raise RuntimeError("1501-byte DF ping unexpectedly received a reply")

        stats = query_stats(proc, responses)
        (rx_packets, _rx_bytes, rx_dropped, rx_errors,
         tx_packets, _tx_bytes, _tx_dropped, tx_errors) = stats
        required = SMALL_PING_COUNT + 1
        if rx_packets < required or tx_packets < required:
            raise RuntimeError(
                "real-TUN packet counts too small: "
                f"rx={rx_packets} tx={tx_packets} required={required}"
            )
        if rx_dropped < 1:
            raise RuntimeError("1501-byte real-TUN ingress was not counted as a drop")
        if rx_errors or tx_errors:
            raise RuntimeError(
                f"real-TUN L3 errors observed: rx={rx_errors} tx={tx_errors}"
            )

        if args.exercise_listeners:
            finish_release = threading.Event()
            finish_cancel_session = start_bridge_session(
                proc,
                responses,
                "bridge-finish-cancel-bbr",
                "bbr",
                BRIDGE_CANCEL_PORTS["finish-bbr"],
                control.make_payload(
                    b"tcpcc-m8.2.6-finish-cancel-bbr:",
                    BRIDGE_FINISH_CANCEL_BYTES,
                ),
                release=finish_release,
            )
            start_bridge_client(finish_cancel_session)
            finish_done = finish_cancel_session["client_done"]
            assert isinstance(finish_done, threading.Event)
            if finish_done.is_set():
                raise RuntimeError(
                    "bridge-finish-cancel-bbr: completed before OP_FINISH"
                )

        control.transact(
            proc,
            responses,
            control.OP_FINISH,
            control.request(control.OP_FINISH),
        )
        if finish_cancel_session is not None:
            tcp_log.append(
                validate_global_cancelled_bridge(
                    finish_cancel_session,
                    responses,
                )
            )
        try:
            returncode = proc.wait(timeout=control.CONTROL_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("hosted real-TUN kernel did not reach final boundary") from exc
        if returncode != 86:
            raise RuntimeError(f"expected hosted kernel exit status 86, got {returncode}")
    except Exception as exc:
        error = exc
        if proc is not None and proc.poll() is None:
            proc.kill()
        if proc is not None:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
    finally:
        if finish_cancel_session is not None:
            release = finish_cancel_session.get("backend_release")
            if isinstance(release, threading.Event):
                release.set()
            client = finish_cancel_session.get("client")
            if isinstance(client, socket.socket):
                client.close()
            listener = finish_cancel_session.get("backend_listener")
            if isinstance(listener, socket.socket):
                listener.close()
        if tun_fd >= 0:
            os.close(tun_fd)
        if proc is not None and proc.stdin is not None:
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass
        stderr = b""
        if proc is not None and proc.stderr is not None:
            stderr = proc.stderr.read()
        args.boot_log.parent.mkdir(parents=True, exist_ok=True)
        args.boot_log.write_bytes(stderr)
        args.responses.write_bytes(bytes(responses))
        args.ping_log.write_text("\n".join(ping_log), encoding="utf-8")
        args.tcp_log.write_text("\n".join(tcp_log) + ("\n" if tcp_log else ""), encoding="utf-8")

    if error is not None:
        print(f"hosted real-TUN TCP test failed: {error}", file=sys.stderr)
        return 1

    assert stats is not None
    print(
        "real TUN TCP passed: CUBIC+BBR"
        f"{' outbound+inbound' if args.exercise_listeners else ' outbound'}; "
        f"rx={stats[0]} tx={stats[4]} rx_dropped={stats[2]} "
        f"host={HOST_IPV4} guest={GUEST_IPV4} "
        f"guest_to_host={args.guest_to_host_bytes} "
        f"host_to_guest={args.host_to_guest_bytes}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

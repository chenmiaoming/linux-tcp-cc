#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import argparse
import errno
import os
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

MAGIC = 0x32434354
VERSION = 1
MAX_PAYLOAD = 256
LOOPBACK = 0x7F000001
PORT = 41042
HOST_IPV4 = 0x0A000001
GUEST_IPV4 = 0x0A000002
GUEST_PREFIX = 24

OP_SOCKET = 1
OP_BIND = 2
OP_LISTEN = 3
OP_CONNECT = 4
OP_ACCEPT = 5
OP_WRITE = 6
OP_READ = 7
OP_CLOSE = 8
OP_SET_CC = 9
OP_GET_CC = 10
OP_FINISH = 11
OP_L3_ATTACH = 12
OP_L3_STATS = 13
OP_HOST_BACKEND_PROBE = 15
OP_BRIDGE_START = 16
OP_BRIDGE_JOIN = 17

REQUEST = struct.Struct("<IHHiIII256s")
RESPONSE = struct.Struct("<IHHiiI256s")
L3_STATS = struct.Struct("<QQQQQQQQ")
HOST_BACKEND_RESULT = struct.Struct("<QiIIIII")
CONTROL_TIMEOUT = 8.0
PACKET_TIMEOUT = 3.0
BURST_PACKETS = 32
SMALL_PACKET_SIZE = 96
MTU_PACKET_SIZE = 1500
OVERSIZE_PACKET_SIZE = 1501
MAX_IGNORED_L3_PACKETS = 128
ICMP_IDENT = 0x4D51
HOST_EVENT_WRITABLE = 1 << 1
HOST_EVENT_HANGUP = 1 << 2
HOST_EVENT_ERROR = 1 << 3
HOST_BACKEND_PAYLOAD_BYTES = 192
HOST_BACKEND_SLOT = 1
HOST_BACKEND_GENERATION = 0x4D3823
HOST_BACKEND_TOKEN = (
    (1 << 63) | (HOST_BACKEND_GENERATION << 32) | HOST_BACKEND_SLOT
)


def make_payload(prefix: bytes, size: int) -> bytes:
    if len(prefix) > size:
        raise ValueError("payload prefix is too large")
    tail = bytes(((index * 73 + 19) & 0xFF) for index in range(size - len(prefix)))
    return prefix + tail


def request(op: int, handle: int = 0, arg0: int = 0, arg1: int = 0,
            data: bytes = b"") -> bytes:
    if len(data) > MAX_PAYLOAD:
        raise ValueError("control payload exceeds ABI limit")
    return REQUEST.pack(MAGIC, VERSION, op, handle, arg0, arg1, len(data),
                        data.ljust(MAX_PAYLOAD, b"\0"))


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_echo_request(total_size: int, sequence: int) -> tuple[bytes, bytes]:
    if total_size < 28:
        raise ValueError("IPv4 ICMP packet is too small")

    payload_len = total_size - 20 - 8
    payload = bytes(((sequence * 29 + index * 17 + 7) & 0xFF)
                    for index in range(payload_len))
    icmp = struct.pack("!BBHHH", 8, 0, 0, ICMP_IDENT, sequence) + payload
    icmp_sum = checksum(icmp)
    icmp = struct.pack("!BBHHH", 8, 0, icmp_sum, ICMP_IDENT, sequence) + payload

    ip_header = struct.pack(
        "!BBHHHBBHII",
        0x45, 0, total_size, sequence & 0xFFFF, 0x4000,
        64, socket.IPPROTO_ICMP, 0, HOST_IPV4, GUEST_IPV4,
    )
    ip_sum = checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBHII",
        0x45, 0, total_size, sequence & 0xFFFF, 0x4000,
        64, socket.IPPROTO_ICMP, ip_sum, HOST_IPV4, GUEST_IPV4,
    )
    return ip_header + icmp, payload


def echo_reply_sequence(packet: bytes) -> int | None:
    """Return our echo-reply sequence, or None for unrelated valid L3 traffic."""
    if len(packet) < 20:
        raise RuntimeError("received truncated L3 packet from tcpcc0")

    version_ihl = packet[0]
    version = version_ihl >> 4
    if version == 6:
        return None
    if version != 4:
        raise RuntimeError(
            f"received invalid L3 packet from tcpcc0: first byte 0x{version_ihl:02x}"
        )
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl:
        raise RuntimeError("received L3 packet with invalid IPv4 IHL")

    total_len = struct.unpack_from("!H", packet, 2)[0]
    if total_len != len(packet):
        raise RuntimeError(
            f"received L3 packet with IPv4 length mismatch: {total_len} != {len(packet)}"
        )
    if checksum(packet[:ihl]) != 0:
        raise RuntimeError("received L3 packet with bad IPv4 checksum")

    if packet[9] != socket.IPPROTO_ICMP:
        return None

    icmp = packet[ihl:]
    if len(icmp) < 8:
        raise RuntimeError("received truncated ICMP packet from tcpcc0")
    if checksum(icmp) != 0:
        raise RuntimeError("received ICMP packet with bad checksum")

    icmp_type, code, _sum, ident, sequence = struct.unpack_from(
        "!BBHHH", icmp, 0
    )
    if (icmp_type, code, ident) != (0, 0, ICMP_IDENT):
        return None
    return sequence


def validate_echo_reply(packet: bytes, sequence: int, payload: bytes) -> None:
    if len(packet) < 28:
        raise RuntimeError(f"ICMP reply {sequence} is truncated")

    version_ihl = packet[0]
    if version_ihl >> 4 != 4:
        raise RuntimeError(f"ICMP reply {sequence} is not IPv4")
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl + 8:
        raise RuntimeError(f"ICMP reply {sequence} has invalid IHL")

    total_len = struct.unpack_from("!H", packet, 2)[0]
    if total_len != len(packet):
        raise RuntimeError(
            f"ICMP reply {sequence} length mismatch: {total_len} != {len(packet)}"
        )
    if checksum(packet[:ihl]) != 0:
        raise RuntimeError(f"ICMP reply {sequence} has bad IPv4 checksum")

    protocol = packet[9]
    src, dst = struct.unpack_from("!II", packet, 12)
    if protocol != socket.IPPROTO_ICMP or src != GUEST_IPV4 or dst != HOST_IPV4:
        raise RuntimeError(f"ICMP reply {sequence} has wrong L3 endpoints")

    icmp = packet[ihl:]
    if checksum(icmp) != 0:
        raise RuntimeError(f"ICMP reply {sequence} has bad ICMP checksum")
    icmp_type, code, _sum, ident, reply_sequence = struct.unpack_from(
        "!BBHHH", icmp, 0
    )
    if (icmp_type, code, ident, reply_sequence) != (0, 0, ICMP_IDENT, sequence):
        raise RuntimeError(f"ICMP reply {sequence} header mismatch")
    if icmp[8:] != payload:
        raise RuntimeError(f"ICMP reply {sequence} payload mismatch")


def read_exact_fd(fd: int, length: int, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    chunks = bytearray()
    while len(chunks) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out after {len(chunks)}/{length} bytes")
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            raise TimeoutError(f"timed out after {len(chunks)}/{length} bytes")
        chunk = os.read(fd, length - len(chunks))
        if not chunk:
            raise EOFError(f"EOF after {len(chunks)}/{length} bytes")
        chunks.extend(chunk)
    return bytes(chunks)


def transact(proc: subprocess.Popen, responses: bytearray, op: int,
             encoded: bytes, expectation: dict | None = None) -> tuple[int, int, bytes]:
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("control pipes are unavailable")

    proc.stdin.write(encoded)
    proc.stdin.flush()
    raw = read_exact_fd(proc.stdout.fileno(), RESPONSE.size, CONTROL_TIMEOUT)
    responses.extend(raw)
    magic, version, response_op, status, handle, length, raw_data = RESPONSE.unpack(raw)

    if magic != MAGIC or version != VERSION or response_op != op:
        raise RuntimeError(
            f"op {op} response header mismatch: magic=0x{magic:08x} "
            f"version={version} op={response_op}"
        )
    expectation = expectation or {}
    expected_status = expectation.get("status", 0)
    if status != expected_status:
        raise RuntimeError(
            f"op {op} returned {status}, expected {expected_status}"
        )
    if length > MAX_PAYLOAD:
        raise RuntimeError(f"op {op} returned oversized payload {length}")

    if "handle" in expectation and handle != expectation["handle"]:
        raise RuntimeError(
            f"op {op} expected handle {expectation['handle']}, got {handle}"
        )
    if "length" in expectation and length != expectation["length"]:
        raise RuntimeError(
            f"op {op} expected length {expectation['length']}, got {length}"
        )
    if "data" in expectation:
        expected_data = expectation["data"]
        if length != len(expected_data) or raw_data[:length] != expected_data:
            raise RuntimeError(f"op {op} payload mismatch")

    return handle, length, raw_data[:length]


def host_backend_payload() -> bytes:
    return bytes(
        ((offset * 37 + 11) & 0xFF)
        for offset in range(HOST_BACKEND_PAYLOAD_BYTES)
    )


def recv_exact_socket(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError(f"host backend EOF after {len(data)}/{length} bytes")
        data.extend(chunk)
    return bytes(data)


def host_backend_echo_worker(listener: socket.socket, expected: bytes,
                             result: dict[str, object]) -> None:
    conn: socket.socket | None = None
    try:
        conn, peer = listener.accept()
        conn.settimeout(CONTROL_TIMEOUT)
        if peer[0] != "127.0.0.1":
            raise RuntimeError(f"host backend accepted unexpected peer {peer[0]}")

        received = recv_exact_socket(conn, len(expected))
        if received != expected:
            raise RuntimeError("host backend received mismatched probe payload")
        if conn.recv(1) != b"":
            raise RuntimeError("host backend received data after the probe payload")

        conn.sendall(received)
        conn.shutdown(socket.SHUT_WR)
        result["received"] = len(received)
    except Exception as exc:
        result["error"] = exc
    finally:
        if conn is not None:
            conn.close()


def exercise_host_backend(proc: subprocess.Popen, responses: bytearray) -> None:
    expected = host_backend_payload()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.settimeout(CONTROL_TIMEOUT)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    backend_result: dict[str, object] = {}
    worker = threading.Thread(
        target=host_backend_echo_worker,
        args=(listener, expected, backend_result),
        daemon=True,
    )
    worker.start()
    listener_closed = False

    try:
        _, length, raw_result = transact(
            proc,
            responses,
            OP_HOST_BACKEND_PROBE,
            request(OP_HOST_BACKEND_PROBE, arg0=LOOPBACK, arg1=port),
        )
        if length != HOST_BACKEND_RESULT.size:
            raise RuntimeError(
                "host backend result size mismatch: "
                f"{length} != {HOST_BACKEND_RESULT.size}"
            )

        worker.join(CONTROL_TIMEOUT)
        if worker.is_alive():
            raise TimeoutError("host backend echo worker did not finish")
        if "error" in backend_result:
            raise RuntimeError(
                "host backend echo worker failed"
            ) from backend_result["error"]
        if backend_result.get("received") != len(expected):
            raise RuntimeError("host backend echo worker did not receive the full payload")

        (token, connect_status, connect_events, terminal_events,
         tx_bytes, rx_bytes, reserved) = HOST_BACKEND_RESULT.unpack(raw_result)
        if token != HOST_BACKEND_TOKEN:
            raise RuntimeError(
                f"host backend token mismatch: 0x{token:016x} != "
                f"0x{HOST_BACKEND_TOKEN:016x}"
            )
        if connect_status != -errno.EINPROGRESS:
            raise RuntimeError(
                "nonblocking host connect returned "
                f"{connect_status}, expected {-errno.EINPROGRESS}"
            )
        if not connect_events & HOST_EVENT_WRITABLE:
            raise RuntimeError("host backend connect did not report WRITABLE")
        if connect_events & HOST_EVENT_ERROR:
            raise RuntimeError("host backend connect unexpectedly reported ERROR")
        if not terminal_events & HOST_EVENT_HANGUP:
            raise RuntimeError("host backend close did not report HANGUP")
        if terminal_events & HOST_EVENT_ERROR:
            raise RuntimeError("host backend close unexpectedly reported ERROR")
        if tx_bytes != len(expected) or rx_bytes != len(expected):
            raise RuntimeError(
                f"host backend byte counts mismatch: tx={tx_bytes} rx={rx_bytes}"
            )
        if reserved:
            raise RuntimeError(f"host backend result reserved field is {reserved}")

        # Reuse the now-closed endpoint to exercise EPOLLERR -> SO_ERROR.
        listener.close()
        listener_closed = True
        transact(
            proc,
            responses,
            OP_HOST_BACKEND_PROBE,
            request(OP_HOST_BACKEND_PROBE, arg0=LOOPBACK, arg1=port),
            {"status": -errno.ECONNREFUSED},
        )
    finally:
        if not listener_closed:
            listener.close()


def exercise_m4_control(proc: subprocess.Popen, responses: bytearray) -> None:
    client_payload = make_payload(b"tcpcc-m4.2-client-to-server:", 192)
    server_payload = make_payload(b"tcpcc-m4.2-server-to-client:", 224)

    commands = [
        (OP_SOCKET, request(OP_SOCKET), {"handle": 1}),
        (OP_BIND, request(OP_BIND, 1, LOOPBACK, PORT), {}),
        (OP_LISTEN, request(OP_LISTEN, 1, 8), {}),
        (OP_SOCKET, request(OP_SOCKET), {"handle": 2}),
        (OP_SET_CC, request(OP_SET_CC, 2, data=b"reno"), {}),
        (OP_GET_CC, request(OP_GET_CC, 2), {"data": b"reno"}),
        (OP_SET_CC, request(OP_SET_CC, 2, data=b"cubic"), {}),
        (OP_GET_CC, request(OP_GET_CC, 2), {"data": b"cubic"}),
        (OP_CONNECT, request(OP_CONNECT, 2, LOOPBACK, PORT), {}),
        (OP_ACCEPT, request(OP_ACCEPT, 1), {"handle": 3}),
        (OP_WRITE, request(OP_WRITE, 2, data=client_payload),
         {"length": len(client_payload)}),
        (OP_READ, request(OP_READ, 3, len(client_payload)),
         {"data": client_payload}),
        (OP_WRITE, request(OP_WRITE, 3, data=server_payload),
         {"length": len(server_payload)}),
        (OP_READ, request(OP_READ, 2, len(server_payload)),
         {"data": server_payload}),
        (OP_CLOSE, request(OP_CLOSE, 3), {}),
        (OP_CLOSE, request(OP_CLOSE, 2), {}),
        (OP_CLOSE, request(OP_CLOSE, 1), {}),
    ]

    for op, encoded, expectation in commands:
        transact(proc, responses, op, encoded, expectation)


def exercise_l3(proc: subprocess.Popen, responses: bytearray,
                host_sock: socket.socket, child_fd: int) -> tuple[int, ...]:
    ifindex, _, _ = transact(
        proc,
        responses,
        OP_L3_ATTACH,
        request(OP_L3_ATTACH, child_fd, GUEST_IPV4, GUEST_PREFIX),
    )
    if ifindex <= 0:
        raise RuntimeError(f"L3 attach returned invalid ifindex {ifindex}")

    expected: dict[int, bytes] = {}
    for sequence in range(1, BURST_PACKETS + 1):
        packet, payload = build_echo_request(SMALL_PACKET_SIZE, sequence)
        expected[sequence] = payload
        host_sock.send(packet)

    mtu_sequence = BURST_PACKETS + 1
    packet, payload = build_echo_request(MTU_PACKET_SIZE, mtu_sequence)
    expected[mtu_sequence] = payload
    host_sock.send(packet)

    deadline = time.monotonic() + PACKET_TIMEOUT
    seen = set()
    ignored = 0
    while len(seen) < len(expected):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("timed out waiting for ICMP echo replies")
        host_sock.settimeout(remaining)
        reply = host_sock.recv(65535)
        sequence = echo_reply_sequence(reply)
        if sequence is None:
            ignored += 1
            if ignored > MAX_IGNORED_L3_PACKETS:
                raise RuntimeError(
                    f"too many unrelated L3 packets from tcpcc0 ({ignored})"
                )
            continue
        if sequence not in expected:
            raise RuntimeError(f"unexpected ICMP echo-reply sequence {sequence}")
        if sequence in seen:
            raise RuntimeError(f"duplicate ICMP sequence {sequence}")
        validate_echo_reply(reply, sequence, expected[sequence])
        seen.add(sequence)

    oversize_sequence = BURST_PACKETS + 2
    packet, _ = build_echo_request(OVERSIZE_PACKET_SIZE, oversize_sequence)
    host_sock.send(packet)
    oversize_deadline = time.monotonic() + 0.25
    while True:
        remaining = oversize_deadline - time.monotonic()
        if remaining <= 0:
            break
        host_sock.settimeout(remaining)
        try:
            unexpected = host_sock.recv(65535)
        except socket.timeout:
            break
        sequence = echo_reply_sequence(unexpected)
        if sequence is None:
            continue
        if sequence == oversize_sequence:
            raise RuntimeError("oversized packet unexpectedly produced an L3 reply")
        raise RuntimeError(f"unexpected late ICMP echo-reply sequence {sequence}")

    _, length, raw_stats = transact(
        proc, responses, OP_L3_STATS, request(OP_L3_STATS)
    )
    if length != L3_STATS.size:
        raise RuntimeError(f"L3 stats size mismatch: {length} != {L3_STATS.size}")
    stats = L3_STATS.unpack(raw_stats)
    (rx_packets, _rx_bytes, rx_dropped, rx_errors,
     tx_packets, _tx_bytes, _tx_dropped, tx_errors) = stats
    required = BURST_PACKETS + 1
    if rx_packets < required or tx_packets < required:
        raise RuntimeError(
            f"L3 packet counts too small: rx={rx_packets} tx={tx_packets} required={required}"
        )
    if rx_dropped < 1:
        raise RuntimeError("oversized L3 ingress was not counted as a drop")
    if rx_errors or tx_errors:
        raise RuntimeError(f"L3 errors observed: rx={rx_errors} tx={tx_errors}")
    return stats


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--boot-log", required=True, type=Path)
    parser.add_argument("--responses", required=True, type=Path)
    args = parser.parse_args()

    responses = bytearray()
    host_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    child_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    child_fd = child_sock.fileno()

    proc = subprocess.Popen(
        [str(args.kernel)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(child_fd,),
    )
    child_sock.close()

    error: Exception | None = None
    stats: tuple[int, ...] | None = None
    try:
        exercise_m4_control(proc, responses)
        exercise_host_backend(proc, responses)
        stats = exercise_l3(proc, responses, host_sock, child_fd)
        transact(proc, responses, OP_FINISH, request(OP_FINISH))
        try:
            returncode = proc.wait(timeout=CONTROL_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("hosted M5.1 kernel did not reach final boundary") from exc
        if returncode != 86:
            raise RuntimeError(f"expected hosted kernel exit status 86, got {returncode}")
    except Exception as exc:  # Preserve diagnostics before returning failure.
        error = exc
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    finally:
        host_sock.close()
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass
        stderr = proc.stderr.read() if proc.stderr is not None else b""
        args.boot_log.parent.mkdir(parents=True, exist_ok=True)
        args.boot_log.write_bytes(stderr)
        args.responses.write_bytes(bytes(responses))

    if error is not None:
        print(f"hosted M5.1 control/data-path test failed: {error}", file=sys.stderr)
        return 1

    assert stats is not None
    print(
        "M5.1 hosted L3 protocol passed: M4.2 socket/CC control, "
        "M8.2.3 host-loopback backend, "
        f"{stats[0]} RX packets, {stats[4]} TX packets, {stats[2]} RX drops"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

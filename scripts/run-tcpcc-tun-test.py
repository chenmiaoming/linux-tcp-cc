#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise hosted Linux ICMP and native TCP/CC through a real host TUN queue."""

import argparse
import fcntl
import importlib.util
import os
import socket
import struct
import subprocess
import sys
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
TCP_TRANSFER_BYTES = 16 * 1024
TCP_CHUNK_BYTES = control.MAX_PAYLOAD


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


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError(f"host TCP EOF after {len(data)}/{length} bytes")
        data.extend(chunk)
    return bytes(data)


def exercise_external_tcp(proc: subprocess.Popen, responses: bytearray,
                          cc_name: str) -> str:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.settimeout(control.CONTROL_TIMEOUT)
    listener.bind((HOST_IPV4, 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    guest_handle: int | None = None
    conn: socket.socket | None = None

    guest_to_host = control.make_payload(
        f"tcpcc-m6.2-{cc_name}-guest-to-host:".encode("ascii"),
        TCP_TRANSFER_BYTES,
    )
    host_to_guest = control.make_payload(
        f"tcpcc-m6.2-{cc_name}-host-to-guest:".encode("ascii"),
        TCP_TRANSFER_BYTES,
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

        for offset in range(0, len(guest_to_host), TCP_CHUNK_BYTES):
            chunk = guest_to_host[offset:offset + TCP_CHUNK_BYTES]
            control.transact(
                proc,
                responses,
                control.OP_WRITE,
                control.request(control.OP_WRITE, guest_handle, data=chunk),
                {"length": len(chunk)},
            )
        received = recv_exact(conn, len(guest_to_host))
        if received != guest_to_host:
            raise RuntimeError(f"{cc_name}: guest-to-host TCP payload mismatch")

        conn.sendall(host_to_guest)
        received = bytearray()
        for offset in range(0, len(host_to_guest), TCP_CHUNK_BYTES):
            chunk = host_to_guest[offset:offset + TCP_CHUNK_BYTES]
            _, _, data = control.transact(
                proc,
                responses,
                control.OP_READ,
                control.request(control.OP_READ, guest_handle, len(chunk)),
                {"data": chunk},
            )
            received.extend(data)
        if bytes(received) != host_to_guest:
            raise RuntimeError(f"{cc_name}: host-to-guest TCP payload mismatch")

        control.transact(
            proc,
            responses,
            control.OP_CLOSE,
            control.request(control.OP_CLOSE, guest_handle),
        )
        guest_handle = None
        return (
            f"{cc_name}: guest={GUEST_IPV4} host={HOST_IPV4}:{port} "
            f"guest_to_host={len(guest_to_host)} host_to_guest={len(host_to_guest)}"
        )
    finally:
        if conn is not None:
            conn.close()
        listener.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--tun-name", required=True)
    parser.add_argument("--boot-log", required=True, type=Path)
    parser.add_argument("--responses", required=True, type=Path)
    parser.add_argument("--ping-log", required=True, type=Path)
    parser.add_argument("--tcp-log", required=True, type=Path)
    args = parser.parse_args()

    tun_fd = attach_tun_queue(args.tun_name)
    responses = bytearray()
    ping_log: list[str] = []
    tcp_log: list[str] = []
    proc: subprocess.Popen | None = None
    error: Exception | None = None
    stats: tuple[int, ...] | None = None

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
            tcp_log.append(exercise_external_tcp(proc, responses, cc_name))

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

        control.transact(proc, responses, control.OP_FINISH, control.request(control.OP_FINISH))
        try:
            returncode = proc.wait(timeout=control.CONTROL_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("hosted M6.2 kernel did not reach final boundary") from exc
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
        print(f"hosted M6.2 real-TUN TCP test failed: {error}", file=sys.stderr)
        return 1

    assert stats is not None
    print(
        "M6.2 real TUN TCP passed: CUBIC+BBR; "
        f"rx={stats[0]} tx={stats[4]} rx_dropped={stats[2]} "
        f"host={HOST_IPV4} guest={GUEST_IPV4}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

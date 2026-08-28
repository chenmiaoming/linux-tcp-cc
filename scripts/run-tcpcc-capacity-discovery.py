#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Discover hosted-service connection capacity without per-flow test threads."""

from __future__ import annotations

import argparse
import errno
import fcntl
import ipaddress
import json
import os
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from tcpcc_control import (  # noqa: E402
    OP_BIND,
    OP_GET_CC,
    OP_L3_ATTACH,
    OP_LISTEN,
    OP_SERVICE_START,
    OP_SERVICE_STATS,
    OP_SERVICE_STOP,
    OP_SET_CC,
    OP_SHUTDOWN,
    OP_SOCKET,
    ControlClient,
    ServiceStats,
    decode_service_stats,
    encode_service_config,
)

SCHEMA = "tcpcc.capacity-discovery.v1"
HOST_IPV4 = "192.0.2.1"
GUEST_IPV4 = "192.0.2.2"
GUEST_PREFIX = 32
PUBLIC_PORT = 18500
BRIDGE_ENCODING_LIMIT = 4095
ACCEPT_BATCH = 64
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
IFF_TUN_EXCL = 0x8000
IFREQ_SIZE = 40
TIMEOUT = 30.0
PAYLOAD_BYTES = 256
BUFFER_HIGH_WATER = re.compile(
    r"M9\.4 bridge buffer high-water ([0-9]+)/262144 bytes, current ([0-9]+)"
)


class CapacityReached(RuntimeError):
    """A stage above the mandatory floor could not be reached."""


def parse_levels(value: str) -> tuple[int, ...]:
    try:
        levels = tuple(int(item, 10) for item in value.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError("levels must be comma-separated integers") from error
    if (
        not levels
        or any(level < 1 or level > BRIDGE_ENCODING_LIMIT for level in levels)
        or tuple(sorted(set(levels))) != levels
    ):
        raise argparse.ArgumentTypeError(
            f"levels must be unique increasing values from 1 through "
            f"{BRIDGE_ENCODING_LIMIT}"
        )
    return levels


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--integration", action="store_true")
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--boot-log", required=True, type=Path)
    parser.add_argument(
        "--levels",
        type=parse_levels,
        default=parse_levels("64,256,1024,2048,4095"),
    )
    parser.add_argument("--minimum", type=int, default=64)
    parser.add_argument("--active-connections", type=int, default=64)
    return parser.parse_args()


def run(command: list[str]) -> None:
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed with {completed.returncode}: {' '.join(command)}\n"
            f"{completed.stdout}"
        )


def create_tun(name: str) -> int:
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    request = bytearray(IFREQ_SIZE)
    struct.pack_into(
        "16sH",
        request,
        0,
        name.encode("ascii"),
        IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL,
    )
    try:
        fcntl.ioctl(fd, TUNSETIFF, request, True)
        actual = bytes(request[:16]).split(b"\0", 1)[0].decode("ascii")
        if actual != name:
            raise RuntimeError(f"TUNSETIFF returned {actual!r}, expected {name!r}")
        run(
            [
                "ip",
                "address",
                "add",
                f"{HOST_IPV4}/32",
                "peer",
                f"{GUEST_IPV4}/32",
                "dev",
                name,
            ]
        )
        run(["ip", "link", "set", "dev", name, "mtu", "1500", "up"])
        return fd
    except BaseException:
        os.close(fd)
        raise


def service_stats(control: ControlClient, handle: int) -> ServiceStats:
    response = control.transact(OP_SERVICE_STATS, handle)
    return decode_service_stats(response.data)


def wait_service_active(
    process: subprocess.Popen[bytes],
    control: ControlClient,
    handle: int,
    target: int,
) -> ServiceStats:
    deadline = time.monotonic() + TIMEOUT
    latest: ServiceStats | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise CapacityReached(
                f"hosted kernel exited with {process.returncode} at target {target}"
            )
        latest = service_stats(control, handle)
        if (
            latest.rejected_connections
            or latest.bridge_start_failures
            or latest.terminal_failures
            or latest.last_error
        ):
            raise CapacityReached(
                f"service rejected or failed a flow at target {target}: "
                f"{asdict(latest)}"
            )
        if (
            latest.accepted_connections >= target
            and latest.active_connections >= target
        ):
            return latest
        time.sleep(0.01)
    raise CapacityReached(
        f"service reached only {asdict(latest) if latest else 'no stats'} "
        f"while waiting for {target} active connections"
    )


def accept_backends(process: subprocess.Popen[bytes], listener: socket.socket,
                    connections: list[socket.socket], target: int) -> None:
    listener.settimeout(0.25)
    deadline = time.monotonic() + TIMEOUT
    while len(connections) < target and time.monotonic() < deadline:
        if process.poll() is not None:
            raise CapacityReached(
                f"hosted kernel exited with {process.returncode} while "
                f"accepting backend connection {len(connections) + 1}/{target}"
            )
        try:
            connection, peer = listener.accept()
        except TimeoutError:
            continue
        if peer[0] != "127.0.0.1":
            connection.close()
            raise CapacityReached(f"backend accepted unexpected peer {peer[0]}")
        connection.settimeout(TIMEOUT)
        connections.append(connection)
    if len(connections) != target:
        raise CapacityReached(
            f"backend accepted {len(connections)}/{target} connections"
        )


def read_exact(connection: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise RuntimeError(
                f"connection ended after {len(result)}/{length} bytes"
            )
        result.extend(chunk)
    return bytes(result)


def active_probe(clients: list[socket.socket],
                 backends: list[socket.socket], count: int) -> dict[str, object]:
    count = min(count, len(clients), len(backends))
    if count < 1:
        raise RuntimeError("active probe has no established connections")
    expected: dict[int, bytes] = {}
    started = time.monotonic()
    for index, client in enumerate(clients[:count]):
        prefix = struct.pack("!I", index) + f"tcpcc-capacity-{index}:".encode("ascii")
        payload = (prefix * ((PAYLOAD_BYTES + len(prefix) - 1) // len(prefix)))[
            :PAYLOAD_BYTES
        ]
        expected[index] = payload
        client.sendall(payload)

    observed_ids: set[int] = set()
    selector = selectors.DefaultSelector()
    pending: dict[int, bytearray] = {}
    try:
        for backend in backends:
            backend.setblocking(False)
            pending[backend.fileno()] = bytearray()
            selector.register(backend, selectors.EVENT_READ)
        deadline = time.monotonic() + TIMEOUT
        while len(observed_ids) < count and time.monotonic() < deadline:
            for key, _events in selector.select(
                max(0.0, deadline - time.monotonic())
            ):
                backend = key.fileobj
                assert isinstance(backend, socket.socket)
                buffer = pending[backend.fileno()]
                try:
                    chunk = backend.recv(PAYLOAD_BYTES - len(buffer))
                except BlockingIOError:
                    continue
                if not chunk:
                    raise RuntimeError("active backend ended before its payload")
                buffer.extend(chunk)
                if len(buffer) != PAYLOAD_BYTES:
                    continue
                payload = bytes(buffer)
                flow_id = struct.unpack("!I", payload[:4])[0]
                if flow_id not in expected or payload != expected[flow_id]:
                    raise RuntimeError(
                        f"active backend received invalid flow {flow_id}"
                    )
                if flow_id in observed_ids:
                    raise RuntimeError(
                        f"active backend received duplicate flow {flow_id}"
                    )
                observed_ids.add(flow_id)
                selector.unregister(backend)
                backend.settimeout(TIMEOUT)
                backend.sendall(payload)
        if len(observed_ids) != count:
            raise TimeoutError(
                f"active backend received {len(observed_ids)}/{count} payloads"
            )
    finally:
        selector.close()
        for backend in backends:
            backend.settimeout(TIMEOUT)

    for index, client in enumerate(clients[:count]):
        if read_exact(client, PAYLOAD_BYTES) != expected[index]:
            raise RuntimeError(f"active client {index} received mismatched echo")
    return {
        "connections": count,
        "payload_bytes_each_direction": PAYLOAD_BYTES,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "status": "passed",
    }


def process_metrics(pid: int) -> dict[str, int]:
    status_values: dict[str, int] = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        key, separator, raw = line.partition(":")
        if separator and key in {"VmRSS", "VmSize", "Threads"}:
            status_values[key] = int(raw.strip().split()[0])
    raw_stat = Path(f"/proc/{pid}/stat").read_text().strip()
    closing = raw_stat.rfind(")")
    fields = raw_stat[closing + 1 :].split()
    return {
        "rss_kib": status_values.get("VmRSS", 0),
        "virtual_kib": status_values.get("VmSize", 0),
        "threads": status_values.get("Threads", 0),
        "host_fds": len(list(Path(f"/proc/{pid}/fd").iterdir())),
        "cpu_ticks": int(fields[11]) + int(fields[12]),
    }


def close_socket(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    connection.close()


def stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def discover(args: argparse.Namespace) -> dict[str, object]:
    kernel = args.kernel.resolve(strict=True)
    if not os.access(kernel, os.X_OK):
        raise PermissionError(f"kernel is not executable: {kernel}")
    tun_name = f"tcpcap{os.getpid():x}"[:15]
    tun_fd = create_tun(tun_name)
    process: subprocess.Popen[bytes] | None = None
    control: ControlClient | None = None
    service_handle: int | None = None
    backend_listener: socket.socket | None = None
    clients: list[socket.socket] = []
    backends: list[socket.socket] = []
    stages: list[dict[str, object]] = []
    capacity_failure: str | None = None
    active_result: dict[str, object] | None = None
    expected_active_bytes: int | None = None
    idle_result: dict[str, object] | None = None
    final_stats: dict[str, object] | None = None
    last_successful = 0
    boot_stream = args.boot_log.open("wb")
    try:
        child_tun_fd = tun_fd
        process = subprocess.Popen(
            [str(kernel)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=boot_stream,
            pass_fds=(tun_fd,),
            close_fds=True,
            bufsize=0,
            start_new_session=True,
        )
        os.close(tun_fd)
        tun_fd = -1
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("hosted kernel did not expose control pipes")
        control = ControlClient(process.stdin, process.stdout, timeout=45.0)
        attached = control.transact(
            OP_L3_ATTACH,
            child_tun_fd,
            int(ipaddress.IPv4Address(GUEST_IPV4)),
            GUEST_PREFIX,
        )
        if attached.handle <= 0:
            raise RuntimeError(f"invalid hosted ifindex {attached.handle}")

        backend_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        backend_listener.bind(("127.0.0.1", 0))
        backend_listener.listen(BRIDGE_ENCODING_LIMIT)
        backend_port = backend_listener.getsockname()[1]

        listener = control.transact(OP_SOCKET).handle
        control.transact(OP_SET_CC, listener, data=b"bbr")
        observed_cc = control.transact(OP_GET_CC, listener).data
        if observed_cc != b"bbr":
            raise RuntimeError(f"hosted listener CC is {observed_cc!r}")
        control.transact(
            OP_BIND,
            listener,
            int(ipaddress.IPv4Address(GUEST_IPV4)),
            PUBLIC_PORT,
        )
        control.transact(OP_LISTEN, listener, BRIDGE_ENCODING_LIMIT)
        service_handle = control.transact(
            OP_SERVICE_START,
            listener,
            data=encode_service_config(
                int(ipaddress.IPv4Address("127.0.0.1")),
                backend_port,
                BRIDGE_ENCODING_LIMIT,
                ACCEPT_BATCH,
            ),
        ).handle
        if service_handle <= 0:
            raise RuntimeError(f"invalid hosted service handle {service_handle}")

        for target in args.levels:
            stage_started = time.monotonic()
            try:
                while len(clients) < target:
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.settimeout(TIMEOUT)
                    try:
                        client.bind((HOST_IPV4, 0))
                        client.connect((GUEST_IPV4, PUBLIC_PORT))
                    except BaseException:
                        client.close()
                        raise
                    clients.append(client)
                accept_backends(process, backend_listener, backends, target)
                stats = wait_service_active(
                    process, control, service_handle, target
                )
            except (CapacityReached, OSError, TimeoutError) as error:
                capacity_failure = f"target {target}: {type(error).__name__}: {error}"
                if len(backends) < args.minimum:
                    raise RuntimeError(
                        f"capacity floor {args.minimum} was not reached: "
                        f"{capacity_failure}"
                    ) from error
                break
            last_successful = target
            if active_result is None and target >= args.active_connections:
                active_result = active_probe(
                    clients, backends, args.active_connections
                )
                expected_active_bytes = (
                    args.active_connections * PAYLOAD_BYTES
                )
            idle_before = process_metrics(process.pid)
            time.sleep(0.25)
            idle_after = process_metrics(process.pid)
            idle_result = {
                "connections": target,
                "seconds": 0.25,
                "cpu_ticks_delta": (
                    idle_after["cpu_ticks"] - idle_before["cpu_ticks"]
                ),
                "process": idle_after,
            }
            stages.append(
                {
                    "target": target,
                    "elapsed_seconds": round(time.monotonic() - stage_started, 6),
                    "service": asdict(stats),
                    "process": process_metrics(process.pid),
                    "idle_cpu_ticks_delta": idle_result["cpu_ticks_delta"],
                }
            )

        reached = last_successful
        if reached < args.minimum:
            raise RuntimeError(
                f"capacity floor {args.minimum} was not reached; observed {reached}"
            )
        if active_result is None:
            raise RuntimeError("active capacity probe was not executed")
        hosted_exit_status = process.poll()
        if hosted_exit_status is None:
            final_stats = asdict(service_stats(control, service_handle))
        elif stages:
            final_stats = dict(stages[-1]["service"])

        for connection in clients:
            close_socket(connection)
        clients.clear()
        for connection in backends:
            close_socket(connection)
        backends.clear()

        if hosted_exit_status is None:
            response = control.transact(OP_SERVICE_STOP, service_handle, 30000)
            final_stats = asdict(decode_service_stats(response.data))
            service_handle = None
            if (
                expected_active_bytes is not None
                and (
                    final_stats["public_to_backend_bytes"]
                    < expected_active_bytes
                    or final_stats["backend_to_public_bytes"]
                    < expected_active_bytes
                )
            ):
                raise RuntimeError(
                    "reaped service byte counters are too small: "
                    f"{final_stats}"
                )
            control.transact(OP_SHUTDOWN)
            status = process.wait(timeout=15)
            if status != 0:
                raise RuntimeError(f"hosted kernel shutdown returned {status}")
        else:
            process.wait(timeout=1)
            service_handle = None
            control = None
        process = None

        return {
            "schema": SCHEMA,
            "status": "passed",
            "encoding_limit": BRIDGE_ENCODING_LIMIT,
            "minimum_required": args.minimum,
            "levels": list(args.levels),
            "reached_connections": reached,
            "capacity_failure": capacity_failure,
            "hosted_exit_status_at_capacity": hosted_exit_status,
            "stages": stages,
            "active_probe": active_result,
            "idle_sample": idle_result,
            "service": final_stats,
        }
    finally:
        for connection in clients:
            close_socket(connection)
        for connection in backends:
            close_socket(connection)
        if service_handle is not None and control is not None:
            try:
                control.transact(
                    OP_SERVICE_STOP,
                    service_handle,
                    30000,
                    allowed_statuses=(0, -errno.ENOENT),
                )
            except BaseException:
                pass
        stop_process(process)
        if backend_listener is not None:
            backend_listener.close()
        if tun_fd >= 0:
            os.close(tun_fd)
        boot_stream.close()


def main() -> int:
    args = parse_args()
    if not args.integration:
        raise SystemExit("--integration is required")
    if (
        args.minimum < 1
        or args.minimum > args.levels[-1]
        or args.active_connections < 1
        or args.active_connections > args.minimum
    ):
        raise SystemExit("minimum and active connection counts must be positive")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.boot_log.parent.mkdir(parents=True, exist_ok=True)
    report: dict[str, object]
    try:
        report = discover(args)
    except BaseException as error:
        report = {
            "schema": SCHEMA,
            "status": "failed",
            "error": f"{type(error).__name__}: {error}",
        }
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        raise

    boot = args.boot_log.read_text(encoding="utf-8", errors="replace")
    matches = BUFFER_HIGH_WATER.findall(boot)
    report["buffer_high_water_bytes"] = int(matches[-1][0]) if matches else None
    report["buffer_current_bytes_at_shutdown"] = (
        int(matches[-1][1]) if matches else None
    )
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

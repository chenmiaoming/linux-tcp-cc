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
import resource
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
    OP_RECLAIM_STATS,
    OP_SERVICE_START,
    OP_SERVICE_STATS,
    OP_SERVICE_STOP,
    OP_SET_CC,
    OP_SHUTDOWN,
    OP_SOCKET,
    ControlClient,
    ReclaimStats,
    RECLAIM_STATE_ACTIVE,
    ServiceStats,
    decode_service_stats,
    decode_reclaim_stats,
    encode_service_config,
)

SCHEMA = "tcpcc.capacity-discovery.v1"
HOST_IPV4 = "192.0.2.1"
GUEST_IPV4 = "192.0.2.2"
GUEST_PREFIX = 32
PUBLIC_PORT = 18500
REUSE_PUBLIC_PORT = 18501
STABILITY_PUBLIC_PORT_BASE = 18600
BRIDGE_SESSION_LIMIT = 1048575
DEFAULT_MEMORY_MIB = 512
ACCEPT_BATCH = 64
LISTEN_BACKLOG = 4096
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
IFF_TUN_EXCL = 0x8000
IFREQ_SIZE = 40
TIMEOUT = 30.0
RECLAIM_TIMEOUT = 120.0
RECLAIM_SAMPLE_SECONDS = 1.0
RECLAIM_MIN_LOAD_DELTA_KIB = 16 * 1024
DEFAULT_STABILITY_ROUNDS = 0
DEFAULT_STABILITY_CONNECTIONS = 8192
DEFAULT_STABILITY_DRIFT_KIB = 8 * 1024
PAYLOAD_BYTES = 256
BUFFER_HIGH_WATER = re.compile(
    r"M9\.4 bridge buffer high-water ([0-9]+)/262144 bytes, current ([0-9]+)"
)
HOST_MEMORY = re.compile(r"tcpcc: M3\.1 host RAM ([0-9]+) MiB at")
L3_PUMP = re.compile(
    r"tcpcc: M11 L3 pump "
    r"rx_packets=([0-9]+) tx_packets=([0-9]+) tx_dropped=([0-9]+) "
    r"rounds=([0-9]+) empty=([0-9]+) rx_irq=([0-9]+) "
    r"tx_wake=([0-9]+) writable_irq=([0-9]+) eagain=([0-9]+) "
    r"arms=([0-9]+) rx_budget=([0-9]+) tx_budget=([0-9]+)"
)
PROCESS_DELTA_FIELDS = (
    "cpu_ticks",
    "voluntary_context_switches",
    "nonvoluntary_context_switches",
    "read_syscalls",
    "write_syscalls",
    "read_bytes",
    "write_bytes",
)


def ensure_driver_fd_capacity(connections: int) -> tuple[int, int]:
    """Keep the Python load generator from becoming the measured limit."""
    required = connections * 2 + 256
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < required:
        target = (
            required
            if hard == resource.RLIM_INFINITY
            else min(required, hard)
        )
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < required:
        raise RuntimeError(
            f"capacity driver needs RLIMIT_NOFILE >= {required}, got {soft}"
        )
    return soft, hard


class CapacityReached(RuntimeError):
    """A stage above the mandatory floor could not be reached."""


def parse_levels(value: str) -> tuple[int, ...]:
    try:
        levels = tuple(int(item, 10) for item in value.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError("levels must be comma-separated integers") from error
    if (
        not levels
        or any(level < 1 or level > BRIDGE_SESSION_LIMIT for level in levels)
        or tuple(sorted(set(levels))) != levels
    ):
        raise argparse.ArgumentTypeError(
            f"levels must be unique increasing values from 1 through "
            f"{BRIDGE_SESSION_LIMIT}"
        )
    return levels


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--integration", action="store_true")
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--boot-log", required=True, type=Path)
    parser.add_argument("--memory-mib", type=int, default=DEFAULT_MEMORY_MIB)
    parser.add_argument(
        "--levels",
        type=parse_levels,
        default=parse_levels("64,256,1024,2048,4095,8192,16384"),
    )
    parser.add_argument("--minimum", type=int, default=16384)
    parser.add_argument("--active-connections", type=int, default=64)
    parser.add_argument("--active-rounds", type=int, default=1)
    parser.add_argument(
        "--stability-rounds", type=int, default=DEFAULT_STABILITY_ROUNDS
    )
    parser.add_argument(
        "--stability-connections",
        type=int,
        default=DEFAULT_STABILITY_CONNECTIONS,
    )
    parser.add_argument(
        "--stability-drift-kib",
        type=int,
        default=DEFAULT_STABILITY_DRIFT_KIB,
    )
    parser.add_argument("--cpu-idle-seconds", type=float, default=0.25)
    parser.add_argument("--max-idle-cpu-percent", type=float)
    parser.add_argument("--cpu-quota-percent", type=int)
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


def reclaim_stats(control: ControlClient) -> ReclaimStats:
    response = control.transact(OP_RECLAIM_STATS)
    stats = decode_reclaim_stats(response.data)
    if (
        stats.state != RECLAIM_STATE_ACTIVE
        or stats.advisory_failures
        or stats.last_error
    ):
        raise RuntimeError(f"guest-free page reclaim is unhealthy: {asdict(stats)}")
    return stats


def start_capacity_service(
    control: ControlClient, backend_port: int, public_port: int
) -> int:
    listener = control.transact(OP_SOCKET).handle
    control.transact(OP_SET_CC, listener, data=b"bbr")
    observed_cc = control.transact(OP_GET_CC, listener).data
    if observed_cc != b"bbr":
        raise RuntimeError(f"hosted listener CC is {observed_cc!r}")
    control.transact(
        OP_BIND,
        listener,
        int(ipaddress.IPv4Address(GUEST_IPV4)),
        public_port,
    )
    control.transact(OP_LISTEN, listener, LISTEN_BACKLOG)
    service_handle = control.transact(
        OP_SERVICE_START,
        listener,
        data=encode_service_config(
            int(ipaddress.IPv4Address("127.0.0.1")),
            backend_port,
            0,
            ACCEPT_BATCH,
        ),
    ).handle
    if service_handle <= 0:
        raise RuntimeError(f"invalid hosted service handle {service_handle}")
    return service_handle


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
        if latest.max_connections != 0:
            raise CapacityReached(
                "capacity service unexpectedly enabled an admission limit: "
                f"{latest.max_connections}"
            )
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


def drain_available_backends(
    process: subprocess.Popen[bytes],
    listener: socket.socket,
    connections: list[socket.socket],
    target: int,
) -> None:
    """Keep the host accept queue from becoming the measured capacity."""
    listener.setblocking(False)
    while len(connections) < target:
        if process.poll() is not None:
            raise CapacityReached(
                f"hosted kernel exited with {process.returncode} while "
                "draining backend connections"
            )
        try:
            connection, peer = listener.accept()
        except BlockingIOError:
            break
        if peer[0] != "127.0.0.1":
            connection.close()
            raise CapacityReached(f"backend accepted unexpected peer {peer[0]}")
        connection.settimeout(TIMEOUT)
        connections.append(connection)


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


def process_metrics(pid: int) -> dict[str, object]:
    status_values: dict[str, int] = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        key, separator, raw = line.partition(":")
        if separator:
            cleaned_key = key.strip()
            if cleaned_key in {
                "VmRSS",
                "VmSize",
                "RssAnon",
                "Threads",
                "voluntary_ctxt_switches",
                "nonvoluntary_ctxt_switches",
            }:
                status_values[cleaned_key] = int(raw.strip().split()[0])
    missing_status = {"VmRSS", "VmSize", "Threads"} - status_values.keys()
    if missing_status:
        raise RuntimeError(
            f"/proc/{pid}/status is missing {sorted(missing_status)}"
        )

    rollup_values: dict[str, int] = {}
    rollup_available = False
    try:
        rollup_lines = Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines()
        rollup_available = True
        for line in rollup_lines:
            key, separator, raw = line.partition(":")
            if separator:
                cleaned_key = key.strip()
                if cleaned_key in {"Rss", "Pss", "Private_Dirty", "Anonymous"}:
                    rollup_values[cleaned_key] = int(raw.strip().split()[0])
    except (FileNotFoundError, PermissionError):
        pass
    if rollup_available:
        missing_rollup = {
            "Rss", "Pss", "Private_Dirty", "Anonymous"
        } - rollup_values.keys()
        if missing_rollup:
            raise RuntimeError(
                f"/proc/{pid}/smaps_rollup is missing {sorted(missing_rollup)}"
            )

    raw_stat = Path(f"/proc/{pid}/stat").read_text().strip()
    closing = raw_stat.rfind(")")
    if closing == -1:
        raise RuntimeError(f"/proc/{pid}/stat has no closing command delimiter")
    fields = raw_stat[closing + 1 :].split()
    if len(fields) <= 12:
        raise RuntimeError(f"/proc/{pid}/stat is truncated")
    cpu_ticks = int(fields[11]) + int(fields[12])

    host_fds = len(list(Path(f"/proc/{pid}/fd").iterdir()))
    io_values: dict[str, int] = {}
    for line in Path(f"/proc/{pid}/io").read_text().splitlines():
        key, separator, raw = line.partition(":")
        if separator and key in {"syscr", "syscw", "read_bytes", "write_bytes"}:
            io_values[key] = int(raw.strip())
    missing_io = {"syscr", "syscw", "read_bytes", "write_bytes"} - io_values.keys()
    if missing_io:
        raise RuntimeError(f"/proc/{pid}/io is missing {sorted(missing_io)}")

    rss_kib = rollup_values.get("Rss", status_values.get("VmRSS", 0))
    virtual_kib = status_values.get("VmSize", 0)
    pss_kib = rollup_values.get("Pss")
    private_dirty_kib = rollup_values.get("Private_Dirty")
    anonymous_kib = rollup_values.get("Anonymous")
    if anonymous_kib is None:
        anonymous_kib = status_values.get("RssAnon")
    threads = status_values.get("Threads", 0)

    return {
        "rss_kib": rss_kib,
        "pss_kib": pss_kib,
        "private_dirty_kib": private_dirty_kib,
        "anonymous_kib": anonymous_kib,
        "virtual_kib": virtual_kib,
        "threads": threads,
        "host_fds": host_fds,
        "cpu_ticks": cpu_ticks,
        "voluntary_context_switches": status_values.get(
            "voluntary_ctxt_switches", 0
        ),
        "nonvoluntary_context_switches": status_values.get(
            "nonvoluntary_ctxt_switches", 0
        ),
        "read_syscalls": io_values["syscr"],
        "write_syscalls": io_values["syscw"],
        "read_bytes": io_values["read_bytes"],
        "write_bytes": io_values["write_bytes"],
        "smaps_rollup_available": rollup_available,
        "rss_source": "smaps_rollup" if rollup_available else "status",
    }


def idle_observation(pid: int, seconds: float) -> dict[str, object]:
    before = process_metrics(pid)
    started = time.monotonic()
    time.sleep(seconds)
    elapsed = time.monotonic() - started
    after = process_metrics(pid)
    deltas = {
        field: int(after[field]) - int(before[field])
        for field in PROCESS_DELTA_FIELDS
    }
    clock_ticks = int(os.sysconf("SC_CLK_TCK"))
    cpu_percent = deltas["cpu_ticks"] * 100.0 / (clock_ticks * elapsed)
    return {
        "seconds": round(elapsed, 6),
        "cpu_percent_one_core": round(cpu_percent, 6),
        "deltas": deltas,
        "before": before,
        "after": after,
    }


def process_metric_deltas(
    before: dict[str, object], after: dict[str, object]
) -> dict[str, int]:
    return {
        field: int(after[field]) - int(before[field])
        for field in PROCESS_DELTA_FIELDS
    }


def place_in_cpu_cgroup(pid: int, quota_percent: int) -> Path:
    cgroup = Path("/sys/fs/cgroup") / f"tcpcc-m11-{pid}"
    cgroup.mkdir()
    try:
        cpu_max = cgroup / "cpu.max"
        if not cpu_max.exists():
            raise RuntimeError("cgroup v2 cpu.max is unavailable")
        period = 100000
        quota = max(1000, period * quota_percent // 100)
        cpu_max.write_text(f"{quota} {period}\n", encoding="ascii")
        (cgroup / "cgroup.procs").write_text(f"{pid}\n", encoding="ascii")
    except BaseException:
        cgroup.rmdir()
        raise
    return cgroup


def remove_cpu_cgroup(cgroup: Path | None) -> None:
    if cgroup is None:
        return
    try:
        cgroup.rmdir()
    except FileNotFoundError:
        pass


def cpu_cgroup_stats(cgroup: Path | None) -> dict[str, int] | None:
    if cgroup is None:
        return None
    values: dict[str, int] = {}
    for line in (cgroup / "cpu.stat").read_text().splitlines():
        key, raw = line.split()
        values[key] = int(raw)
    return values


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


def summarize_stability(
    baseline_anonymous_kib: int,
    drift_allowance_kib: int,
    expected_rounds: int,
    rounds: list[dict[str, object]],
) -> dict[str, object]:
    """Gate and summarize post-reclaim floors without hiding round detail."""
    if len(rounds) != expected_rounds:
        raise RuntimeError(
            f"memory stability completed {len(rounds)}/{expected_rounds} rounds"
        )
    floors = [
        round_sample["post_reclaim_process"]["anonymous_kib"]
        for round_sample in rounds
    ]
    if any(value is None for value in floors):
        raise RuntimeError("anonymous RSS is required for the stability gate")
    observed_floors = [int(value) for value in floors]
    ceiling = baseline_anonymous_kib + drift_allowance_kib
    maximum_floor = max(observed_floors, default=baseline_anonymous_kib)
    if maximum_floor > ceiling:
        raise RuntimeError(
            "post-reclaim anonymous RSS ratcheted above the stability ceiling: "
            f"baseline={baseline_anonymous_kib} KiB "
            f"allowance={drift_allowance_kib} KiB "
            f"ceiling={ceiling} KiB floors={observed_floors}"
        )
    late_floors = observed_floors[-min(3, len(observed_floors)) :]
    return {
        "status": "passed",
        "rounds": expected_rounds,
        "baseline_anonymous_kib": baseline_anonymous_kib,
        "drift_allowance_kib": drift_allowance_kib,
        "ceiling_anonymous_kib": ceiling,
        "post_reclaim_anonymous_kib": observed_floors,
        "maximum_post_reclaim_anonymous_kib": maximum_floor,
        "maximum_drift_kib": maximum_floor - baseline_anonymous_kib,
        "final_drift_kib": (
            observed_floors[-1] - baseline_anonymous_kib
            if observed_floors
            else 0
        ),
        "late_round_span_kib": (
            max(late_floors) - min(late_floors) if late_floors else 0
        ),
    }


def discover(args: argparse.Namespace) -> dict[str, object]:
    kernel = args.kernel.resolve(strict=True)
    if not os.access(kernel, os.X_OK):
        raise PermissionError(f"kernel is not executable: {kernel}")
    tun_name = f"tcpcap{os.getpid():x}"[:15]
    tun_fd = create_tun(tun_name)
    process: subprocess.Popen[bytes] | None = None
    cpu_cgroup: Path | None = None
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
    ready_sample: dict[str, object] | None = None
    post_drain_sample: dict[str, object] | None = None
    post_drain_idle_samples: list[dict[str, object]] = []
    reclaim_samples: list[dict[str, object]] = []
    reclaim_result: dict[str, object] | None = None
    post_reclaim_idle_samples: list[dict[str, object]] = []
    reuse_sample: dict[str, object] | None = None
    stability_round_samples: list[dict[str, object]] = []
    stability_result: dict[str, object] | None = None
    hosted_exit_status: int | None = None
    reached = 0
    last_successful = 0

    def lifecycle_report(status: str, error: BaseException | None = None) -> dict[str, object]:
        report: dict[str, object] = {
            "schema": SCHEMA,
            "status": status,
            "encoding_limit": BRIDGE_SESSION_LIMIT,
            "admission_limit": 0,
            "hosted_memory_mib": args.memory_mib,
            "cpu_configuration": {
                "quota_percent": args.cpu_quota_percent,
                "idle_seconds": args.cpu_idle_seconds,
                "max_idle_cpu_percent": args.max_idle_cpu_percent,
            },
            "cpu_cgroup": cpu_cgroup_stats(cpu_cgroup),
            "minimum_required": args.minimum,
            "levels": list(args.levels),
            "reached_connections": reached,
            "capacity_failure": capacity_failure,
            "hosted_exit_status_at_capacity": hosted_exit_status,
            "ready_sample": ready_sample,
            "stages": stages,
            "active_probe": active_result,
            "idle_sample": idle_result,
            "post_drain_sample": post_drain_sample,
            "post_drain_idle_samples": post_drain_idle_samples,
            "reclaim_samples": reclaim_samples,
            "reclaim_result": reclaim_result,
            "post_reclaim_idle_samples": post_reclaim_idle_samples,
            "reuse_sample": reuse_sample,
            "stability_configuration": {
                "rounds": args.stability_rounds,
                "connections_per_round": args.stability_connections,
                "drift_allowance_kib": args.stability_drift_kib,
                "public_port_base": STABILITY_PUBLIC_PORT_BASE,
            },
            "stability_rounds": stability_round_samples,
            "stability_result": stability_result,
            "service": final_stats,
        }
        if error is not None:
            report["error"] = f"{type(error).__name__}: {error}"
        return report

    boot_stream = args.boot_log.open("wb")
    try:
        child_tun_fd = tun_fd
        process = subprocess.Popen(
            [str(kernel), f"--memory-mib={args.memory_mib}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=boot_stream,
            pass_fds=(tun_fd,),
            close_fds=True,
            bufsize=0,
            start_new_session=True,
        )
        if args.cpu_quota_percent is not None:
            cpu_cgroup = place_in_cpu_cgroup(
                process.pid, args.cpu_quota_percent
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
        backend_listener.listen(LISTEN_BACKLOG)
        backend_port = backend_listener.getsockname()[1]

        service_handle = start_capacity_service(
            control, backend_port, PUBLIC_PORT
        )

        ready_stats = service_stats(control, service_handle)
        ready_sample = {
            "service": asdict(ready_stats),
            "process": process_metrics(process.pid),
            "reclaim": asdict(reclaim_stats(control)),
            "idle": idle_observation(process.pid, args.cpu_idle_seconds),
        }
        if (
            args.max_idle_cpu_percent is not None
            and ready_sample["idle"]["cpu_percent_one_core"]
            > args.max_idle_cpu_percent
        ):
            raise RuntimeError(
                "ready idle CPU exceeded ceiling: "
                f"{ready_sample['idle']['cpu_percent_one_core']}% > "
                f"{args.max_idle_cpu_percent}%"
            )

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
                    if len(clients) % ACCEPT_BATCH == 0:
                        drain_available_backends(
                            process,
                            backend_listener,
                            backends,
                            len(clients),
                        )
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
                active_before = process_metrics(process.pid)
                active_started = time.monotonic()
                for _round in range(args.active_rounds):
                    active_probe(clients, backends, args.active_connections)
                active_elapsed = time.monotonic() - active_started
                active_after = process_metrics(process.pid)
                active_deltas = process_metric_deltas(
                    active_before, active_after
                )
                active_bytes = (
                    args.active_connections
                    * PAYLOAD_BYTES
                    * args.active_rounds
                    * 2
                )
                active_cpu_seconds = (
                    active_deltas["cpu_ticks"]
                    / int(os.sysconf("SC_CLK_TCK"))
                )
                active_result = {
                    "status": "passed",
                    "connections": args.active_connections,
                    "rounds": args.active_rounds,
                    "payload_bytes_each_direction": PAYLOAD_BYTES,
                    "payload_bytes_each_direction_per_round": PAYLOAD_BYTES,
                    "total_bidirectional_bytes": active_bytes,
                    "elapsed_seconds": round(active_elapsed, 6),
                    "process_deltas": active_deltas,
                    "cpu_seconds": round(active_cpu_seconds, 6),
                    "cpu_seconds_per_gib": round(
                        active_cpu_seconds * (1024 ** 3) / active_bytes, 6
                    ),
                }
                expected_active_bytes = (
                    args.active_connections
                    * PAYLOAD_BYTES
                    * args.active_rounds
                )
            idle_seconds = (
                args.cpu_idle_seconds
                if target == args.levels[-1]
                else 0.25
            )
            observation = idle_observation(process.pid, idle_seconds)
            idle_result = {
                "connections": target,
                "seconds": observation["seconds"],
                "cpu_ticks_delta": observation["deltas"]["cpu_ticks"],
                "process": observation["after"],
                **observation,
            }
            if (
                target == args.levels[-1]
                and args.max_idle_cpu_percent is not None
                and observation["cpu_percent_one_core"]
                > args.max_idle_cpu_percent
            ):
                raise RuntimeError(
                    f"{target}-connection idle CPU exceeded ceiling: "
                    f"{observation['cpu_percent_one_core']}% > "
                    f"{args.max_idle_cpu_percent}%"
                )
            stages.append(
                {
                    "target": target,
                    "elapsed_seconds": round(time.monotonic() - stage_started, 6),
                    "service": asdict(stats),
                    "process": process_metrics(process.pid),
                    "reclaim": asdict(reclaim_stats(control)),
                    "idle": idle_result,
                    "idle_cpu_ticks_delta": idle_result["deltas"][
                        "cpu_ticks"
                    ],
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
        if hosted_exit_status is not None:
            if stages:
                final_stats = dict(stages[-1]["service"])
            raise RuntimeError(
                "hosted kernel exited after reaching capacity with status "
                f"{hosted_exit_status}"
            )

        for connection in clients:
            close_socket(connection)
        clients.clear()
        for connection in backends:
            close_socket(connection)
        backends.clear()

        if (
            hosted_exit_status is None
            and service_handle is not None
            and control is not None
        ):
            response = control.transact(OP_SERVICE_STOP, service_handle, 30000)
            drain_stats = decode_service_stats(response.data)
            service_handle = None
            final_stats = asdict(drain_stats)
            if drain_stats.active_connections != 0:
                raise RuntimeError(
                    f"stopped service retained active flows: {final_stats}"
                )
            if (
                expected_active_bytes is not None
                and (
                    drain_stats.public_to_backend_bytes < expected_active_bytes
                    or drain_stats.backend_to_public_bytes < expected_active_bytes
                )
            ):
                raise RuntimeError(
                    "reaped capacity service byte counters are too small: "
                    f"{final_stats}"
                )
            post_drain_sample = {
                "service": final_stats,
                "process": process_metrics(process.pid),
                "reclaim": asdict(reclaim_stats(control)),
            }

            for window_index in range(2):
                window_before = process_metrics(process.pid)
                time.sleep(0.5)
                window_after = process_metrics(process.pid)
                post_drain_idle_samples.append(
                    {
                        "window": window_index + 1,
                        "seconds": 0.5,
                        "cpu_ticks_delta": (
                            window_after["cpu_ticks"]
                            - window_before["cpu_ticks"]
                        ),
                        "process": window_after,
                        "reclaim": asdict(reclaim_stats(control)),
                    }
                )

            ready_anonymous = ready_sample["process"]["anonymous_kib"]
            stage_anonymous = [
                stage["process"]["anonymous_kib"] for stage in stages
            ]
            if ready_anonymous is None or any(
                value is None for value in stage_anonymous
            ):
                raise RuntimeError(
                    "anonymous RSS is required for the M10.3 reclaim gate"
                )
            peak_anonymous = max(stage_anonymous)
            load_delta = peak_anonymous - ready_anonymous
            if load_delta < RECLAIM_MIN_LOAD_DELTA_KIB:
                raise RuntimeError(
                    "capacity load did not create the minimum anonymous-RSS "
                    f"delta: {load_delta} < {RECLAIM_MIN_LOAD_DELTA_KIB} KiB"
                )
            target_anonymous = ready_anonymous + load_delta // 2
            pre_drain_discard = stages[-1]["reclaim"][
                "successful_discard_bytes"
            ]
            reclaim_started = time.monotonic()
            reclaim_deadline = reclaim_started + RECLAIM_TIMEOUT
            while time.monotonic() < reclaim_deadline:
                observed_reclaim = reclaim_stats(control)
                observed_process = process_metrics(process.pid)
                sample = {
                    "elapsed_seconds": round(
                        time.monotonic() - reclaim_started, 6
                    ),
                    "process": observed_process,
                    "reclaim": asdict(observed_reclaim),
                }
                reclaim_samples.append(sample)
                observed_anonymous = observed_process["anonymous_kib"]
                if (
                    observed_anonymous is not None
                    and observed_anonymous <= target_anonymous
                    and observed_reclaim.successful_discard_bytes
                    > pre_drain_discard
                ):
                    reclaim_result = {
                        "status": "passed",
                        "ready_anonymous_kib": ready_anonymous,
                        "peak_anonymous_kib": peak_anonymous,
                        "load_delta_kib": load_delta,
                        "target_anonymous_kib": target_anonymous,
                        "observed_anonymous_kib": observed_anonymous,
                        "recovered_load_delta_ratio": round(
                            (peak_anonymous - observed_anonymous) / load_delta,
                            6,
                        ),
                        "successful_discard_delta_bytes": (
                            observed_reclaim.successful_discard_bytes
                            - pre_drain_discard
                        ),
                        "elapsed_seconds": sample["elapsed_seconds"],
                    }
                    break
                time.sleep(RECLAIM_SAMPLE_SECONDS)
            if reclaim_result is None:
                latest = reclaim_samples[-1] if reclaim_samples else None
                raise RuntimeError(
                    "guest-free page reclaim did not recover half of the "
                    f"load-induced anonymous RSS within {RECLAIM_TIMEOUT}s: "
                    f"target={target_anonymous} KiB latest={latest}"
                )

            for window_index in range(2):
                window_before = process_metrics(process.pid)
                time.sleep(0.5)
                window_after = process_metrics(process.pid)
                post_reclaim_idle_samples.append(
                    {
                        "window": window_index + 1,
                        "seconds": 0.5,
                        "cpu_ticks_delta": (
                            window_after["cpu_ticks"]
                            - window_before["cpu_ticks"]
                        ),
                        "process": window_after,
                        "reclaim": asdict(reclaim_stats(control)),
                    }
                )

            reuse_target = min(args.active_connections, 64)
            reuse_clients: list[socket.socket] = []
            reuse_backends: list[socket.socket] = []
            reuse_probe_result: dict[str, object] | None = None
            reuse_metrics: dict[str, object] | None = None
            reuse_active_stats: dict[str, object] | None = None
            reuse_stop_stats: dict[str, object] | None = None
            try:
                service_handle = start_capacity_service(
                    control, backend_port, REUSE_PUBLIC_PORT
                )
                for _ in range(reuse_target):
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.settimeout(TIMEOUT)
                    try:
                        client.bind((HOST_IPV4, 0))
                        client.connect((GUEST_IPV4, REUSE_PUBLIC_PORT))
                    except BaseException:
                        client.close()
                        raise
                    reuse_clients.append(client)
                    if len(reuse_clients) % ACCEPT_BATCH == 0:
                        drain_available_backends(
                            process,
                            backend_listener,
                            reuse_backends,
                            len(reuse_clients),
                        )
                accept_backends(
                    process, backend_listener, reuse_backends, reuse_target
                )
                wait_service_active(
                    process, control, service_handle, reuse_target
                )
                reuse_probe_result = active_probe(
                    reuse_clients, reuse_backends, reuse_target
                )
                reuse_metrics = process_metrics(process.pid)
                reuse_active_stats = asdict(
                    service_stats(control, service_handle)
                )
            finally:
                for connection in reuse_clients:
                    close_socket(connection)
                reuse_clients.clear()
                for connection in reuse_backends:
                    close_socket(connection)
                reuse_backends.clear()

            response = control.transact(OP_SERVICE_STOP, service_handle, 30000)
            reuse_stop_stats = asdict(decode_service_stats(response.data))
            service_handle = None
            if (
                reuse_stop_stats["active_connections"] != 0
                or reuse_stop_stats["public_to_backend_bytes"]
                < reuse_target * PAYLOAD_BYTES
                or reuse_stop_stats["backend_to_public_bytes"]
                < reuse_target * PAYLOAD_BYTES
            ):
                raise RuntimeError(
                    f"reused service did not stop cleanly: {reuse_stop_stats}"
                )

            reuse_sample = {
                "connections": reuse_target,
                "public_port": REUSE_PUBLIC_PORT,
                "active_probe": reuse_probe_result,
                "active_service": reuse_active_stats,
                "stopped_service": reuse_stop_stats,
                "process": reuse_metrics,
                "reclaim": asdict(reclaim_stats(control)),
            }

            stability_baseline = post_reclaim_idle_samples[-1]["process"][
                "anonymous_kib"
            ]
            if stability_baseline is None:
                raise RuntimeError(
                    "anonymous RSS is required for the multi-round stability gate"
                )
            stability_ceiling = stability_baseline + args.stability_drift_kib
            for round_index in range(args.stability_rounds):
                public_port = STABILITY_PUBLIC_PORT_BASE + round_index
                round_started = time.monotonic()
                pre_round_process = process_metrics(process.pid)
                probe_count = min(args.active_connections, 64)
                round_reclaim_samples: list[dict[str, object]] = []
                round_sample: dict[str, object] = {
                    "round": round_index + 1,
                    "status": "running",
                    "connections": args.stability_connections,
                    "public_port": public_port,
                    "pre_round_process": pre_round_process,
                    "reclaim_samples": round_reclaim_samples,
                }
                stability_round_samples.append(round_sample)
                round_probe: dict[str, object] | None = None
                active_round_process: dict[str, object] | None = None
                active_round_reclaim: ReclaimStats | None = None
                active_round_service: ServiceStats | None = None

                service_handle = start_capacity_service(
                    control, backend_port, public_port
                )
                try:
                    while len(clients) < args.stability_connections:
                        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        client.settimeout(TIMEOUT)
                        try:
                            client.bind((HOST_IPV4, 0))
                            client.connect((GUEST_IPV4, public_port))
                        except BaseException:
                            client.close()
                            raise
                        clients.append(client)
                        if len(clients) % ACCEPT_BATCH == 0:
                            drain_available_backends(
                                process,
                                backend_listener,
                                backends,
                                len(clients),
                            )
                    accept_backends(
                        process,
                        backend_listener,
                        backends,
                        args.stability_connections,
                    )
                    active_round_service = wait_service_active(
                        process,
                        control,
                        service_handle,
                        args.stability_connections,
                    )
                    round_probe = active_probe(
                        clients, backends, probe_count
                    )
                    active_round_process = process_metrics(process.pid)
                    active_round_reclaim = reclaim_stats(control)
                finally:
                    for connection in clients:
                        close_socket(connection)
                    clients.clear()
                    for connection in backends:
                        close_socket(connection)
                    backends.clear()

                if (
                    active_round_process is None
                    or active_round_reclaim is None
                    or active_round_service is None
                    or round_probe is None
                ):
                    raise RuntimeError(
                        f"stability round {round_index + 1} did not reach load"
                    )
                round_sample.update(
                    {
                        "active_process": active_round_process,
                        "active_service": asdict(active_round_service),
                        "active_reclaim": asdict(active_round_reclaim),
                        "active_probe": round_probe,
                    }
                )

                response = control.transact(
                    OP_SERVICE_STOP, service_handle, 30000
                )
                stopped_round_service = decode_service_stats(response.data)
                service_handle = None
                round_sample["stopped_service"] = asdict(
                    stopped_round_service
                )
                if (
                    stopped_round_service.active_connections != 0
                    or stopped_round_service.max_connections != 0
                    or stopped_round_service.rejected_connections
                    or stopped_round_service.bridge_start_failures
                    or stopped_round_service.public_to_backend_bytes
                    < probe_count * PAYLOAD_BYTES
                    or stopped_round_service.backend_to_public_bytes
                    < probe_count * PAYLOAD_BYTES
                ):
                    raise RuntimeError(
                        f"stability round {round_index + 1} did not stop "
                        f"cleanly: {asdict(stopped_round_service)}"
                    )
                round_reclaim_started = time.monotonic()
                post_reclaim_process: dict[str, object] | None = None
                post_reclaim_stats: ReclaimStats | None = None
                while (
                    time.monotonic() - round_reclaim_started
                    < RECLAIM_TIMEOUT
                ):
                    if process.poll() is not None:
                        raise RuntimeError(
                            "hosted kernel exited during stability reclaim "
                            f"round {round_index + 1} with {process.returncode}"
                        )
                    observed_reclaim = reclaim_stats(control)
                    observed_process = process_metrics(process.pid)
                    round_reclaim_samples.append(
                        {
                            "elapsed_seconds": round(
                                time.monotonic() - round_reclaim_started, 6
                            ),
                            "process": observed_process,
                            "reclaim": asdict(observed_reclaim),
                        }
                    )
                    observed_anonymous = observed_process["anonymous_kib"]
                    if (
                        observed_anonymous is not None
                        and observed_anonymous <= stability_ceiling
                        and observed_reclaim.successful_discard_bytes
                        > active_round_reclaim.successful_discard_bytes
                    ):
                        post_reclaim_process = observed_process
                        post_reclaim_stats = observed_reclaim
                        break
                    time.sleep(RECLAIM_SAMPLE_SECONDS)
                if post_reclaim_process is None or post_reclaim_stats is None:
                    raise RuntimeError(
                        "multi-round reclaim did not return to the stability "
                        f"ceiling in round {round_index + 1}: "
                        f"ceiling={stability_ceiling} KiB "
                        f"latest={round_reclaim_samples[-1] if round_reclaim_samples else None}"
                    )

                idle_before = process_metrics(process.pid)
                time.sleep(0.5)
                idle_after = process_metrics(process.pid)
                post_idle_anonymous = idle_after["anonymous_kib"]
                if (
                    post_idle_anonymous is None
                    or post_idle_anonymous > stability_ceiling
                ):
                    raise RuntimeError(
                        "post-reclaim RSS exceeded the stability ceiling after "
                        f"idle round {round_index + 1}: "
                        f"ceiling={stability_ceiling} KiB observed={post_idle_anonymous}"
                    )
                round_sample.update(
                    {
                        "status": "passed",
                        "elapsed_seconds": round(
                            time.monotonic() - round_started, 6
                        ),
                        "post_reclaim_process": idle_after,
                        "post_reclaim": asdict(post_reclaim_stats),
                        "successful_discard_delta_bytes": (
                            post_reclaim_stats.successful_discard_bytes
                            - active_round_reclaim.successful_discard_bytes
                        ),
                        "idle_seconds": 0.5,
                        "idle_cpu_ticks_delta": (
                            idle_after["cpu_ticks"] - idle_before["cpu_ticks"]
                        ),
                    }
                )

            if args.stability_rounds:
                stability_result = summarize_stability(
                    stability_baseline,
                    args.stability_drift_kib,
                    args.stability_rounds,
                    stability_round_samples,
                )

        if (
            post_drain_sample is None
            or len(post_drain_idle_samples) != 2
            or reclaim_result is None
            or len(post_reclaim_idle_samples) != 2
            or reuse_sample is None
            or (
                args.stability_rounds
                and (
                    stability_result is None
                    or len(stability_round_samples) != args.stability_rounds
                )
            )
        ):
            raise RuntimeError("hosted memory lifecycle did not complete")

        control.transact(OP_SHUTDOWN)
        status = process.wait(timeout=15)
        if status != 0:
            raise RuntimeError(f"hosted kernel shutdown returned {status}")
        process = None

        return lifecycle_report("passed")
    except BaseException as error:
        error.tcpcc_partial_report = lifecycle_report("failed", error)
        raise
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
        remove_cpu_cgroup(cpu_cgroup)
        cpu_cgroup = None
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
        or args.memory_mib < 128
        or args.active_connections < 1
        or args.active_connections > args.minimum
        or args.active_rounds < 1
        or args.active_rounds > 1024
        or args.stability_rounds < 0
        or args.stability_rounds > 32
        or args.stability_connections < 1
        or args.stability_connections > BRIDGE_SESSION_LIMIT
        or args.stability_drift_kib < 0
        or args.cpu_idle_seconds < 0.1
        or args.cpu_idle_seconds > 60.0
        or (
            args.max_idle_cpu_percent is not None
            and (
                args.max_idle_cpu_percent < 0.0
                or args.max_idle_cpu_percent > 100.0
            )
        )
        or (
            args.cpu_quota_percent is not None
            and (
                args.cpu_quota_percent < 1
                or args.cpu_quota_percent > 100
            )
        )
        or STABILITY_PUBLIC_PORT_BASE + max(args.stability_rounds - 1, 0)
        > 65535
        or (
            args.stability_rounds
            and args.active_connections > args.stability_connections
        )
    ):
        raise SystemExit(
            "memory must be at least 128 MiB; connection, stability-round, "
            "stability-drift, CPU, and public-port bounds must be valid"
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.boot_log.parent.mkdir(parents=True, exist_ok=True)
    report: dict[str, object]
    nofile_soft: int | None = None
    nofile_hard: int | None = None
    try:
        required_connections = max(
            args.levels[-1],
            args.stability_connections if args.stability_rounds else 0,
        )
        nofile_soft, nofile_hard = ensure_driver_fd_capacity(
            required_connections
        )
        report = discover(args)
        report["driver_nofile_soft"] = nofile_soft
        report["driver_nofile_hard"] = nofile_hard
        report["driver_ephemeral_port_range"] = [
            int(value)
            for value in Path(
                "/proc/sys/net/ipv4/ip_local_port_range"
            ).read_text().split()
        ]
        boot = args.boot_log.read_text(encoding="utf-8", errors="replace")
        memory_matches = HOST_MEMORY.findall(boot)
        if not memory_matches or int(memory_matches[-1]) != args.memory_mib:
            raise RuntimeError(
                f"hosted memory boot report does not match {args.memory_mib} MiB"
            )
        report["observed_hosted_memory_mib"] = int(memory_matches[-1])
        buffer_matches = BUFFER_HIGH_WATER.findall(boot)
        report["buffer_high_water_bytes"] = (
            int(buffer_matches[-1][0]) if buffer_matches else None
        )
        report["buffer_current_bytes_at_shutdown"] = (
            int(buffer_matches[-1][1]) if buffer_matches else None
        )
        pump_matches = L3_PUMP.findall(boot)
        if not pump_matches:
            raise RuntimeError("M11 L3 packet-pump telemetry is missing")
        pump_values = [int(value) for value in pump_matches[-1]]
        pump_names = (
            "rx_packets",
            "tx_packets",
            "tx_dropped",
            "io_rounds",
            "empty_rounds",
            "rx_irq_events",
            "tx_queue_wakeups",
            "tx_writable_events",
            "tx_eagain",
            "writable_arms",
            "rx_budget_yields",
            "tx_budget_yields",
        )
        report["l3_pump"] = dict(zip(pump_names, pump_values, strict=True))
        if report["l3_pump"]["empty_rounds"]:
            raise RuntimeError(
                "L3 packet pump observed empty wake rounds: "
                f"{report['l3_pump']['empty_rounds']}"
            )
        if (
            report["l3_pump"]["tx_queue_wakeups"]
            > (
                report["l3_pump"]["tx_packets"]
                + report["l3_pump"]["tx_dropped"]
            )
        ):
            raise RuntimeError(
                "L3 TX wakeups exceeded transmitted packets: "
                f"{report['l3_pump']['tx_queue_wakeups']} > "
                f"{report['l3_pump']['tx_packets']} + "
                f"{report['l3_pump']['tx_dropped']} dropped"
            )
    except BaseException as error:
        partial_report = getattr(error, "tcpcc_partial_report", None)
        report = (
            partial_report
            if isinstance(partial_report, dict)
            else {
                "schema": SCHEMA,
                "status": "failed",
                "error": f"{type(error).__name__}: {error}",
            }
        )
        if nofile_soft is not None and nofile_hard is not None:
            report["driver_nofile_soft"] = nofile_soft
            report["driver_nofile_hard"] = nofile_hard
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        raise

    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

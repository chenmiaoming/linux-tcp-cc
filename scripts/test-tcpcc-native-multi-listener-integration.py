#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Privileged end-to-end regression for native multi-listener tcpcc CLI routes."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_ADDRESS = "203.0.113.10"
CLIENT_ADDRESS = "203.0.113.20"
PUBLIC_PORTS = (18554, 18555)
BACKEND_PORTS = (18564, 18565)
REQUESTS = (b"tcpcc-native-multi-a", b"tcpcc-native-multi-b")
RESPONSES = (b"tcpcc-native-multi-reply-a", b"tcpcc-native-multi-reply-b")
TIMEOUT = 20.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--integration", action="store_true")
    parser.add_argument(
        "--firewall-backend",
        choices=("nft-lib", "nft-exec", "iptables"),
    )
    parser.add_argument(
        "--iptables-variant",
        choices=("iptables", "iptables-nft", "iptables-legacy"),
        default="iptables",
    )
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--backend-server", action="store_true")
    parser.add_argument("--client", action="store_true")
    parser.add_argument("--address")
    parser.add_argument("--port", type=int)
    parser.add_argument("--request")
    parser.add_argument("--response")
    return parser.parse_args()


def run(
    command: list[str],
    *,
    check: bool = True,
    timeout: float = TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed with {completed.returncode}: {' '.join(command)}\n"
            f"{completed.stdout}"
        )
    return completed


def ns_command(namespace: str, *command: str) -> list[str]:
    return ["ip", "netns", "exec", namespace, *command]


def wait_pipe_line(process: subprocess.Popen[str], label: str) -> str:
    if process.stdout is None:
        raise RuntimeError(f"{label} stdout is unavailable")
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read()
            raise RuntimeError(
                f"{label} exited with {process.returncode} before readiness: {output}"
            )
        remaining = deadline - time.monotonic()
        readable, _writable, _exceptional = select.select(
            [process.stdout.fileno()], [], [], max(0.0, remaining)
        )
        if readable:
            line = process.stdout.readline()
            if line:
                return line.rstrip("\n")
    raise TimeoutError(f"{label} did not become ready within {TIMEOUT:.0f}s")


def backend_server(port: int, request: bytes, response: bytes) -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.settimeout(TIMEOUT)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    print("backend-ready", flush=True)
    connection: socket.socket | None = None
    try:
        connection, peer = listener.accept()
        connection.settimeout(TIMEOUT)
        if peer[0] != "127.0.0.1":
            raise RuntimeError(f"backend accepted unexpected peer {peer[0]}")
        received = bytearray()
        while len(received) < len(request):
            chunk = connection.recv(len(request) - len(received))
            if not chunk:
                break
            received.extend(chunk)
        if bytes(received) != request:
            raise RuntimeError(
                f"backend {port} received {bytes(received)!r}, expected {request!r}"
            )
        connection.sendall(response)
        connection.shutdown(socket.SHUT_WR)
        return 0
    finally:
        if connection is not None:
            connection.close()
        listener.close()


def client(address: str, port: int, request: bytes, response: bytes) -> int:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(TIMEOUT)
    try:
        connection.connect((address, port))
        connection.sendall(request)
        received = bytearray()
        while len(received) < len(response):
            chunk = connection.recv(len(response) - len(received))
            if not chunk:
                break
            received.extend(chunk)
        if bytes(received) != response:
            raise RuntimeError(
                f"client {port} received {bytes(received)!r}, expected {response!r}"
            )
    finally:
        connection.close()
    print(f"client-{port}-passed")
    return 0


def read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="replace")
    documents: list[dict[str, object]] = []
    lines = raw.splitlines()
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            if index == len(lines) - 1 and not raw.endswith("\n"):
                continue
            raise
        if not isinstance(document, dict):
            raise RuntimeError(f"status line is not a JSON object: {line}")
        documents.append(document)
    return documents


def wait_event(
    path: Path,
    process: subprocess.Popen[bytes],
    event: str,
) -> dict[str, object]:
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        for document in read_events(path):
            if document.get("event") == event:
                return document
        status = process.poll()
        if status is not None:
            raise RuntimeError(
                f"tcpcc exited with {status} before {event!r}: {read_events(path)!r}"
            )
        time.sleep(0.05)
    raise TimeoutError(f"tcpcc did not emit {event!r} within {TIMEOUT:.0f}s")


def stop_process(process: subprocess.Popen[object] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def assert_firewall_removed(
    router: str,
    backend: str,
    iptables_variant: str,
    resource: str,
) -> None:
    if backend in {"nft-lib", "nft-exec"}:
        result = run(
            ns_command(router, "nft", "list", "table", "ip", resource),
            check=False,
        )
        if result.returncode == 0:
            raise RuntimeError(f"owned nftables table {resource} survived shutdown")
        return

    result = run(
        ns_command(
            router,
            iptables_variant,
            "--wait",
            "-t",
            "nat",
            "-S",
            resource,
        ),
        check=False,
    )
    if result.returncode == 0:
        raise RuntimeError(f"owned iptables chain {resource} survived shutdown")
    prerouting = run(
        ns_command(
            router,
            iptables_variant,
            "--wait",
            "-t",
            "nat",
            "-S",
            "PREROUTING",
        )
    )
    if resource in prerouting.stdout:
        raise RuntimeError(f"PREROUTING still references owned chain {resource}")


def publish_artifacts(output_dir: Path | None, sources: tuple[Path, ...]) -> None:
    if output_dir is None:
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    for source in sources:
        if source.exists():
            shutil.copy2(source, output_dir / source.name)


def integration(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise PermissionError("--integration requires root")
    if args.firewall_backend is None or args.kernel is None:
        raise ValueError("--integration requires --firewall-backend and --kernel")
    kernel = args.kernel.resolve(strict=True)
    if not os.access(kernel, os.X_OK):
        raise PermissionError(f"kernel image is not executable: {kernel}")

    suffix = secrets.token_hex(3)
    router = f"tcpcc-ml-r-{suffix}"
    client_ns = f"tcpcc-ml-c-{suffix}"
    router_link = f"mr{suffix}"
    client_link = f"mc{suffix}"
    tun_name = f"tcpml{suffix}"
    namespaces: list[str] = []
    backends: list[subprocess.Popen[str]] = []
    backend_logs: list[Path] = []
    clients: list[subprocess.Popen[str]] = []
    client_logs: list[Path] = []
    tcpcc_process: subprocess.Popen[bytes] | None = None
    ready: dict[str, object] | None = None

    with tempfile.TemporaryDirectory(prefix="tcpcc-native-multi-") as temporary:
        temp = Path(temporary)
        event_log = temp / "tcpcc-native-multi-events.jsonl"
        diagnostic_log = temp / "tcpcc-native-multi.log"
        try:
            for namespace in (router, client_ns):
                run(["ip", "netns", "add", namespace])
                namespaces.append(namespace)
            run(
                [
                    "ip",
                    "link",
                    "add",
                    router_link,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    client_link,
                ]
            )
            run(["ip", "link", "set", router_link, "netns", router])
            run(["ip", "link", "set", client_link, "netns", client_ns])
            for namespace, link, address in (
                (router, router_link, PUBLIC_ADDRESS),
                (client_ns, client_link, CLIENT_ADDRESS),
            ):
                run(["ip", "-n", namespace, "link", "set", "lo", "up"])
                run(
                    [
                        "ip",
                        "-n",
                        namespace,
                        "address",
                        "add",
                        f"{address}/24",
                        "dev",
                        link,
                    ]
                )
                run(["ip", "-n", namespace, "link", "set", link, "up"])

            for setting in (
                "net.ipv4.ip_forward=1",
                "net.ipv4.tcp_congestion_control=cubic",
                "net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.default.rp_filter=0",
                f"net.ipv4.conf.{router_link}.rp_filter=0",
            ):
                run(ns_command(router, "sysctl", "-q", "-w", setting))

            for index, (port, request, response) in enumerate(
                zip(BACKEND_PORTS, REQUESTS, RESPONSES)
            ):
                log = temp / f"backend-{index}.log"
                backend_logs.append(log)
                stderr = log.open("wb")
                process = subprocess.Popen(
                    ns_command(
                        router,
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "--backend-server",
                        "--port",
                        str(port),
                        "--request",
                        request.decode("ascii"),
                        "--response",
                        response.decode("ascii"),
                    ),
                    stdout=subprocess.PIPE,
                    stderr=stderr,
                    text=True,
                    bufsize=1,
                )
                stderr.close()
                backends.append(process)
                if wait_pipe_line(process, f"backend {index}") != "backend-ready":
                    raise RuntimeError(f"backend {index} emitted invalid readiness")

            command = ns_command(
                router,
                str(ROOT / "tcpcc"),
                "--forward",
                f"{PUBLIC_ADDRESS}:{PUBLIC_PORTS[0]}=127.0.0.1:{BACKEND_PORTS[0]}",
                "--forward",
                f"{PUBLIC_ADDRESS}:{PUBLIC_PORTS[1]}=127.0.0.1:{BACKEND_PORTS[1]}",
                "--cc",
                "bbr",
                "--kernel",
                str(kernel),
                "--firewall-backend",
                args.firewall_backend,
                "--tun-name",
                tun_name,
                "--max-connections",
                "4",
                "--shutdown-grace-period",
                "5",
            )
            if args.firewall_backend == "iptables":
                command.extend(("--iptables-variant", args.iptables_variant))

            event_stream = event_log.open("wb")
            diagnostic_stream = diagnostic_log.open("wb")
            tcpcc_process = subprocess.Popen(
                command,
                stdout=event_stream,
                stderr=diagnostic_stream,
                start_new_session=True,
            )
            event_stream.close()
            diagnostic_stream.close()

            ready = wait_event(event_log, tcpcc_process, "ready")
            if ready.get("cc") != "bbr" or ready.get("tun") != tun_name:
                raise RuntimeError(f"ready event base contract mismatch: {ready}")
            if ready.get("firewall_backend") != args.firewall_backend:
                raise RuntimeError(f"ready event firewall backend mismatch: {ready}")
            if ready.get("listener_count") != 2:
                raise RuntimeError(f"ready event listener_count mismatch: {ready}")
            routes = ready.get("routes")
            if not isinstance(routes, list) or len(routes) != 2:
                raise RuntimeError(f"ready event routes mismatch: {ready}")

            expected = [
                {
                    "listen": f"{PUBLIC_ADDRESS}:{PUBLIC_PORTS[index]}",
                    "backend": f"127.0.0.1:{BACKEND_PORTS[index]}",
                }
                for index in range(2)
            ]
            resources: list[str] = []
            for index, route in enumerate(routes):
                if not isinstance(route, dict):
                    raise RuntimeError(f"route {index} is not an object: {route!r}")
                if route.get("listen") != expected[index]["listen"] or route.get(
                    "backend"
                ) != expected[index]["backend"]:
                    raise RuntimeError(
                        f"route {index} mapping mismatch: {route!r}, expected {expected[index]!r}"
                    )
                resource = route.get("firewall_resource")
                if not isinstance(resource, str) or not resource:
                    raise RuntimeError(f"route {index} lacks firewall ownership: {route!r}")
                resources.append(resource)
            if len(set(resources)) != 2:
                raise RuntimeError(f"multi-listener routes reused firewall resource: {resources}")
            if (
                ready.get("listen") != expected[0]["listen"]
                or ready.get("backend") != expected[0]["backend"]
                or ready.get("firewall_resource") != resources[0]
            ):
                raise RuntimeError(f"legacy first-route ready fields changed: {ready}")

            outer_cc = run(
                ns_command(router, "sysctl", "-n", "net.ipv4.tcp_congestion_control")
            ).stdout.strip()
            if outer_cc != "cubic":
                raise RuntimeError(
                    f"outer namespace congestion control changed unexpectedly: {outer_cc!r}"
                )

            for index, (port, request, response) in enumerate(
                zip(PUBLIC_PORTS, REQUESTS, RESPONSES)
            ):
                log = temp / f"client-{index}.log"
                client_logs.append(log)
                stream = log.open("wb")
                process = subprocess.Popen(
                    ns_command(
                        client_ns,
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "--client",
                        "--address",
                        PUBLIC_ADDRESS,
                        "--port",
                        str(port),
                        "--request",
                        request.decode("ascii"),
                        "--response",
                        response.decode("ascii"),
                    ),
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    text=False,
                )
                stream.close()
                clients.append(process)

            for index, process in enumerate(clients):
                status = process.wait(timeout=TIMEOUT)
                if status != 0:
                    raise RuntimeError(
                        f"client {index} failed with {status}: "
                        f"{client_logs[index].read_text(errors='replace')}"
                    )
            for index, process in enumerate(backends):
                status = process.wait(timeout=TIMEOUT)
                if status != 0:
                    raise RuntimeError(
                        f"backend {index} failed with {status}: "
                        f"{backend_logs[index].read_text(errors='replace')}"
                    )

            tcpcc_process.send_signal(signal.SIGTERM)
            status = tcpcc_process.wait(timeout=TIMEOUT)
            if status != 0:
                raise RuntimeError(
                    f"tcpcc shutdown returned {status}: "
                    f"{diagnostic_log.read_text(errors='replace')}"
                )

            events = read_events(event_log)
            stats = [item for item in events if item.get("event") == "service-stats"]
            stopped = [item for item in events if item.get("event") == "stopped"]
            if len(stats) != 1 or len(stopped) != 1:
                raise RuntimeError(f"terminal event contract mismatch: {events!r}")
            final = stats[0]
            if (
                final.get("accepted_connections") != 2
                or final.get("completed_connections") != 2
                or final.get("active_connections") != 0
                or final.get("rejected_connections") != 0
                or final.get("bridge_start_failures") != 0
                or final.get("terminal_failures") != 0
                or final.get("last_error") != 0
            ):
                raise RuntimeError(f"aggregate service stats mismatch: {final}")
            if stopped[0].get("clean") is not True or stopped[0].get("signal") != signal.SIGTERM:
                raise RuntimeError(f"clean shutdown event mismatch: {stopped[0]}")

            if run(
                ns_command(router, "ip", "link", "show", "dev", tun_name),
                check=False,
            ).returncode == 0:
                raise RuntimeError(f"owned TUN {tun_name} survived clean shutdown")
            for resource in resources:
                assert_firewall_removed(
                    router,
                    args.firewall_backend,
                    args.iptables_variant,
                    resource,
                )

            print(
                "native-multi-listener: "
                f"backend={args.firewall_backend} routes=2 routing=isolated "
                "accepted=2 completed=2 cleanup=clean"
            )
            return 0
        finally:
            stop_process(tcpcc_process)
            for process in clients:
                stop_process(process)
            for process in backends:
                stop_process(process)
            publish_artifacts(
                args.output_dir,
                (event_log, diagnostic_log, *backend_logs, *client_logs),
            )
            for namespace in reversed(namespaces):
                run(["ip", "netns", "delete", namespace], check=False)


def require_text(args: argparse.Namespace, name: str) -> str:
    value = getattr(args, name)
    if not isinstance(value, str):
        raise ValueError(f"--{name.replace('_', '-')} is required")
    return value


def main() -> int:
    args = parse_args()
    if args.backend_server:
        if args.port is None:
            raise ValueError("--backend-server requires --port")
        return backend_server(
            args.port,
            require_text(args, "request").encode("ascii"),
            require_text(args, "response").encode("ascii"),
        )
    if args.client:
        if args.port is None:
            raise ValueError("--client requires --port")
        return client(
            require_text(args, "address"),
            args.port,
            require_text(args, "request").encode("ascii"),
            require_text(args, "response").encode("ascii"),
        )
    if args.integration:
        return integration(args)
    raise ValueError("select --integration, --backend-server, or --client")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"native multi-listener integration failed: {error}", file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Privileged end-to-end M8.4 ingress test across one firewall backend."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import select
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_ADDRESS = "203.0.113.10"
CLIENT_ADDRESS = "203.0.113.20"
PUBLIC_PORT = 18454
BACKEND_PORT = 18455
HOSTED_ADDRESS = "198.18.0.2"
HOSTED_PREFIX = 32
HTTP_BODY = b"tcpcc-m8.4-backend\n"
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
    parser.add_argument("--http-client", action="store_true")
    parser.add_argument("--port", type=int)
    parser.add_argument("--address")
    return parser.parse_args()


def backend_server(port: int) -> int:
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
        request = bytearray()
        while len(request) < 16 * 1024:
            chunk = connection.recv(4096)
            if not chunk:
                break
            request.extend(chunk)
            if b"\r\n\r\n" in request:
                break
        if not bytes(request).startswith(b"GET /m8.4 HTTP/1.1\r\n"):
            raise RuntimeError(f"backend received invalid request {bytes(request)!r}")
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Connection: close\r\n"
            b"Content-Type: text/plain\r\n"
            + f"Content-Length: {len(HTTP_BODY)}\r\n\r\n".encode("ascii")
            + HTTP_BODY
        )
        connection.sendall(response)
        connection.shutdown(socket.SHUT_WR)
        return 0
    finally:
        if connection is not None:
            connection.close()
        listener.close()


def http_client(address: str, port: int) -> int:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(TIMEOUT)
    try:
        connection.connect((address, port))
        connection.sendall(
            b"GET /m8.4 HTTP/1.1\r\n"
            + f"Host: {address}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
        )
        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    finally:
        connection.close()
    header, separator, body = bytes(response).partition(b"\r\n\r\n")
    if separator != b"\r\n\r\n" or not header.startswith(b"HTTP/1.1 200 OK\r\n"):
        raise RuntimeError(f"client received invalid HTTP response {bytes(response)!r}")
    if body != HTTP_BODY:
        raise RuntimeError(f"client body is {body!r}, expected {HTTP_BODY!r}")
    print(body.decode("ascii").strip())
    return 0


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
            [process.stdout.fileno()], [], [], max(0, remaining)
        )
        if readable:
            line = process.stdout.readline()
            if line:
                return line.rstrip("\n")
    raise TimeoutError(f"{label} did not become ready within {TIMEOUT:.0f}s")


def read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    documents: list[dict[str, object]] = []
    raw = path.read_text(encoding="utf-8", errors="replace")
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
            raise RuntimeError(f"status line is not an object: {line}")
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
                f"tcpcc exited with {status} before {event!r}; "
                f"events={read_events(path)!r}"
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


def assert_cleaned(
    router: str,
    tun_name: str,
    backend: str,
    firewall_resource: str,
    iptables_variant: str,
) -> None:
    link = run(
        ns_command(router, "ip", "link", "show", "dev", tun_name),
        check=False,
    )
    if link.returncode == 0:
        raise RuntimeError(f"owned TUN {tun_name} survived tcpcc shutdown")

    if backend in {"nft-lib", "nft-exec"}:
        resource = run(
            ns_command(
                router,
                "nft",
                "list",
                "table",
                "ip",
                firewall_resource,
            ),
            check=False,
        )
        if resource.returncode == 0:
            raise RuntimeError(
                f"owned nftables table {firewall_resource} survived shutdown"
            )
    else:
        resource = run(
            ns_command(
                router,
                iptables_variant,
                "--wait",
                "-t",
                "nat",
                "-S",
                firewall_resource,
            ),
            check=False,
        )
        if resource.returncode == 0:
            raise RuntimeError(
                f"owned iptables chain {firewall_resource} survived shutdown"
            )
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
        if firewall_resource in prerouting.stdout:
            raise RuntimeError(
                f"PREROUTING still jumps to owned chain {firewall_resource}"
            )


def publish_artifacts(
    output_dir: Path | None,
    sources: tuple[Path, ...],
) -> None:
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
    if ipaddress.IPv4Address(CLIENT_ADDRESS) in ipaddress.IPv4Network(
        f"{HOSTED_ADDRESS}/{HOSTED_PREFIX}", strict=False
    ):
        raise AssertionError("client fixture must be outside the hosted prefix")

    suffix = secrets.token_hex(3)
    router = f"tcpcc-router-{suffix}"
    client = f"tcpcc-client-{suffix}"
    router_link = f"tr{suffix}"
    client_link = f"tc{suffix}"
    tun_name = f"tcpe2e{suffix}"
    backend_process: subprocess.Popen[str] | None = None
    tcpcc_process: subprocess.Popen[bytes] | None = None
    namespaces: list[str] = []

    with tempfile.TemporaryDirectory(prefix="tcpcc-m84-") as temporary:
        temp = Path(temporary)
        event_log = temp / "tcpcc-events.jsonl"
        diagnostic_log = temp / "tcpcc.log"
        backend_log = temp / "backend.log"
        try:
            for namespace in (router, client):
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
            run(["ip", "link", "set", client_link, "netns", client])
            for namespace, link, address in (
                (router, router_link, PUBLIC_ADDRESS),
                (client, client_link, CLIENT_ADDRESS),
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
                "net.ipv4.tcp_congestion_control=bbr",
                "net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.default.rp_filter=0",
                f"net.ipv4.conf.{router_link}.rp_filter=0",
            ):
                run(ns_command(router, "sysctl", "-q", "-w", setting))

            backend_stderr = backend_log.open("wb")
            backend_process = subprocess.Popen(
                ns_command(
                    router,
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--backend-server",
                    "--port",
                    str(BACKEND_PORT),
                ),
                stdout=subprocess.PIPE,
                stderr=backend_stderr,
                text=True,
                bufsize=1,
            )
            backend_stderr.close()
            if wait_pipe_line(backend_process, "backend") != "backend-ready":
                raise RuntimeError("backend emitted an invalid readiness marker")

            command = ns_command(
                router,
                str(ROOT / "tcpcc"),
                "--listen",
                f"{PUBLIC_ADDRESS}:{PUBLIC_PORT}",
                "--backend",
                f"127.0.0.1:{BACKEND_PORT}",
                "--cc",
                "bbr",
                "--kernel",
                str(kernel),
                "--firewall-backend",
                args.firewall_backend,
                "--tun-name",
                tun_name,
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
                raise RuntimeError(f"tcpcc readiness contract mismatch: {ready}")
            if ready.get("firewall_backend") != args.firewall_backend:
                raise RuntimeError(f"tcpcc selected an unexpected backend: {ready}")

            client_result = run(
                ns_command(
                    client,
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--http-client",
                    "--address",
                    PUBLIC_ADDRESS,
                    "--port",
                    str(PUBLIC_PORT),
                )
            )
            if client_result.stdout.strip() != HTTP_BODY.decode("ascii").strip():
                raise RuntimeError(f"client output mismatch: {client_result.stdout!r}")
            backend_status = backend_process.wait(timeout=TIMEOUT)
            if backend_status != 0:
                raise RuntimeError(
                    f"backend exited with {backend_status}: "
                    f"{backend_log.read_text(errors='replace')}"
                )
            opened = wait_event(event_log, tcpcc_process, "connection-opened")
            if opened.get("accepted_cc") != "bbr":
                raise RuntimeError(f"accepted socket CC was not verified: {opened}")

            tcpcc_process.send_signal(signal.SIGTERM)
            tcpcc_status = tcpcc_process.wait(timeout=TIMEOUT)
            if tcpcc_status != 0:
                raise RuntimeError(
                    f"tcpcc exited with {tcpcc_status}: "
                    f"{diagnostic_log.read_text(errors='replace')}"
                )
            stopped = next(
                (
                    document
                    for document in read_events(event_log)
                    if document.get("event") == "stopped"
                ),
                None,
            )
            if stopped is None or stopped.get("clean") is not True:
                raise RuntimeError(f"tcpcc emitted no clean stop event: {stopped}")
            firewall_resource = ready.get("firewall_resource")
            if not isinstance(firewall_resource, str) or not firewall_resource:
                raise RuntimeError("readiness omitted the owned firewall resource")
            assert_cleaned(
                router,
                tun_name,
                args.firewall_backend,
                firewall_resource,
                args.iptables_variant,
            )

            print(
                json.dumps(
                    {
                        "schema": "tcpcc.cli-integration.v1",
                        "backend": args.firewall_backend,
                        "iptables_variant": args.iptables_variant,
                        "client": f"{CLIENT_ADDRESS}/24",
                        "hosted": f"{HOSTED_ADDRESS}/{HOSTED_PREFIX}",
                        "accepted_cc": opened["accepted_cc"],
                        "http_body": HTTP_BODY.decode("ascii").strip(),
                        "shutdown": "clean",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            publish_artifacts(
                args.output_dir,
                (event_log, diagnostic_log, backend_log),
            )
            return 0
        except BaseException as error:
            diagnostics = (
                diagnostic_log.read_text(encoding="utf-8", errors="replace")
                if diagnostic_log.exists()
                else ""
            )
            events = read_events(event_log) if event_log.exists() else []
            publish_artifacts(
                args.output_dir,
                (event_log, diagnostic_log, backend_log),
            )
            raise RuntimeError(
                f"M8.4 CLI integration failed: {error}\n"
                f"events={events!r}\n"
                f"tcpcc diagnostics:\n{diagnostics}"
            ) from error
        finally:
            stop_process(tcpcc_process)
            stop_process(backend_process)
            for namespace in reversed(namespaces):
                run(["ip", "netns", "delete", namespace], check=False)


def main() -> int:
    args = parse_args()
    if args.backend_server:
        if args.port is None:
            raise ValueError("--backend-server requires --port")
        return backend_server(args.port)
    if args.http_client:
        if args.address is None or args.port is None:
            raise ValueError("--http-client requires --address and --port")
        return http_client(args.address, args.port)
    if not args.integration:
        raise ValueError("refusing privileged setup without --integration")
    return integration(args)


if __name__ == "__main__":
    raise SystemExit(main())

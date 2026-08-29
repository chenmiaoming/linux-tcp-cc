#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Privileged IPv6 public-endpoint integration for the tcpcc CLI."""

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
PUBLIC_ADDRESS = "fd42:7463:7063:1::10"
CLIENT_ADDRESS = "fd42:7463:7063:1::20"
PUBLIC_NETWORK = "fd42:7463:7063:1::/64"
HOSTED_ADDRESS = "fd00:198:18::2"
PUBLIC_PORT = 18654
BACKEND_PORT = 18655
BODY = b"tcpcc-ipv6-public-endpoint\n"
TIMEOUT = 30.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--integration", action="store_true")
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--backend-server", action="store_true")
    parser.add_argument("--ipv6-client", action="store_true")
    return parser.parse_args()


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=TIMEOUT,
    )
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed with {completed.returncode}: {' '.join(command)}\n"
            f"{completed.stdout}"
        )
    return completed


def ns(namespace: str, *command: str) -> list[str]:
    return ["ip", "netns", "exec", namespace, *command]


def backend_server() -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.settimeout(TIMEOUT)
    listener.bind(("127.0.0.1", BACKEND_PORT))
    listener.listen(1)
    print("backend-ready", flush=True)
    connection, peer = listener.accept()
    try:
        connection.settimeout(TIMEOUT)
        if peer[0] != "127.0.0.1":
            raise RuntimeError(f"unexpected backend peer {peer!r}")
        request = connection.recv(4096)
        if request != b"ipv6-through-hosted-linux":
            raise RuntimeError(f"unexpected backend payload {request!r}")
        connection.sendall(BODY)
        connection.shutdown(socket.SHUT_WR)
    finally:
        connection.close()
        listener.close()
    return 0


def ipv6_client() -> int:
    connection = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    connection.settimeout(TIMEOUT)
    try:
        connection.bind((CLIENT_ADDRESS, 0, 0, 0))
        connection.connect((PUBLIC_ADDRESS, PUBLIC_PORT, 0, 0))
        connection.sendall(b"ipv6-through-hosted-linux")
        connection.shutdown(socket.SHUT_WR)
        received = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            received.extend(chunk)
    finally:
        connection.close()
    if bytes(received) != BODY:
        raise RuntimeError(f"IPv6 client received {bytes(received)!r}")
    print(BODY.decode("ascii").strip())
    return 0


def wait_line(process: subprocess.Popen[str]) -> str:
    if process.stdout is None:
        raise RuntimeError("backend stdout is unavailable")
    readable, _writable, _exceptional = select.select(
        [process.stdout.fileno()], [], [], TIMEOUT
    )
    if not readable:
        raise TimeoutError("backend did not become ready")
    return process.stdout.readline().strip()


def read_events(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


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
        if process.poll() is not None:
            raise RuntimeError(
                f"tcpcc exited with {process.returncode}; events={read_events(path)!r}"
            )
        time.sleep(0.05)
    raise TimeoutError(f"tcpcc did not emit {event!r}")


def stop(process: subprocess.Popen[object] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def integration(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise PermissionError("--integration requires root")
    if args.kernel is None:
        raise ValueError("--integration requires --kernel")
    kernel = args.kernel.resolve(strict=True)
    suffix = secrets.token_hex(3)
    router = f"tcpcc-v6-router-{suffix}"
    client = f"tcpcc-v6-client-{suffix}"
    router_link = f"v6r{suffix}"
    client_link = f"v6c{suffix}"
    tun_name = f"tcpv6{suffix}"
    namespaces: list[str] = []
    backend: subprocess.Popen[str] | None = None
    tcpcc: subprocess.Popen[bytes] | None = None

    with tempfile.TemporaryDirectory(prefix="tcpcc-ipv6-") as temporary:
        temporary_path = Path(temporary)
        events_path = temporary_path / "events.jsonl"
        diagnostic_path = temporary_path / "tcpcc.log"
        backend_path = temporary_path / "backend.log"
        try:
            for namespace in (router, client):
                run(["ip", "netns", "add", namespace])
                namespaces.append(namespace)
            run([
                "ip", "link", "add", router_link, "type", "veth",
                "peer", "name", client_link,
            ])
            run(["ip", "link", "set", router_link, "netns", router])
            run(["ip", "link", "set", client_link, "netns", client])
            for namespace, link, address in (
                (router, router_link, PUBLIC_ADDRESS),
                (client, client_link, CLIENT_ADDRESS),
            ):
                run(["ip", "-n", namespace, "link", "set", "lo", "up"])
                run([
                    "ip", "-n", namespace, "-6", "address", "add",
                    f"{address}/64", "dev", link, "nodad",
                ])
                run(["ip", "-n", namespace, "link", "set", link, "up"])
                run([
                    "ip", "-n", namespace, "-6", "route", "replace",
                    PUBLIC_NETWORK, "dev", link, "src", address,
                ])
            run(ns(router, "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1"))
            run(ns(router, "sysctl", "-q", "-w", "net.ipv4.tcp_congestion_control=bbr"))

            backend_log = backend_path.open("wb")
            backend = subprocess.Popen(
                ns(router, sys.executable, str(Path(__file__).resolve()), "--backend-server"),
                stdout=subprocess.PIPE,
                stderr=backend_log,
                text=True,
                bufsize=1,
            )
            backend_log.close()
            if wait_line(backend) != "backend-ready":
                raise RuntimeError("backend readiness marker mismatch")

            event_stream = events_path.open("wb")
            diagnostic_stream = diagnostic_path.open("wb")
            tcpcc = subprocess.Popen(
                ns(
                    router,
                    str(ROOT / "tcpcc"),
                    "--listen", f"[{PUBLIC_ADDRESS}]:{PUBLIC_PORT}",
                    "--backend", f"127.0.0.1:{BACKEND_PORT}",
                    "--cc", "bbr",
                    "--kernel", str(kernel),
                    "--firewall-backend", "nft-lib",
                    "--tun-name", tun_name,
                ),
                stdout=event_stream,
                stderr=diagnostic_stream,
                start_new_session=True,
            )
            event_stream.close()
            diagnostic_stream.close()
            ready = wait_event(events_path, tcpcc, "ready")
            if ready.get("listen") != f"[{PUBLIC_ADDRESS}]:{PUBLIC_PORT}":
                raise RuntimeError(f"IPv6 readiness mismatch: {ready!r}")
            if ready.get("hosted_address") != HOSTED_ADDRESS:
                raise RuntimeError(f"IPv6 hosted address mismatch: {ready!r}")

            client_result = run(
                ns(client, sys.executable, str(Path(__file__).resolve()), "--ipv6-client")
            )
            if client_result.stdout.strip() != BODY.decode("ascii").strip():
                raise RuntimeError(f"IPv6 client output mismatch: {client_result.stdout!r}")
            if backend.wait(timeout=TIMEOUT) != 0:
                raise RuntimeError(backend_path.read_text(errors="replace"))
            closed = wait_event(events_path, tcpcc, "connection-closed")
            if closed.get("status") != 0:
                raise RuntimeError(f"IPv6 bridge failed: {closed!r}")

            tcpcc.send_signal(signal.SIGTERM)
            if tcpcc.wait(timeout=TIMEOUT) != 0:
                raise RuntimeError(diagnostic_path.read_text(errors="replace"))
            documents = read_events(events_path)
            if not any(item.get("event") == "stopped" for item in documents):
                raise RuntimeError("tcpcc did not stop cleanly")
            if run(ns(router, "ip", "link", "show", "dev", tun_name), check=False).returncode == 0:
                raise RuntimeError("IPv6 TUN survived shutdown")
            resource = ready.get("firewall_resource")
            if not isinstance(resource, str):
                raise RuntimeError("readiness omitted nftables resource")
            if run(
                ns(router, "nft", "list", "table", "ip6", resource),
                check=False,
            ).returncode == 0:
                raise RuntimeError("IPv6 nftables table survived shutdown")

            print(json.dumps({
                "schema": "tcpcc.ipv6-integration.v1",
                "public": f"[{PUBLIC_ADDRESS}]:{PUBLIC_PORT}",
                "hosted": HOSTED_ADDRESS,
                "backend": f"127.0.0.1:{BACKEND_PORT}",
                "firewall": "nft-ip6",
                "bridge": "clean",
                "shutdown": "clean",
            }, sort_keys=True, separators=(",", ":")))
            if args.output_dir is not None:
                args.output_dir.mkdir(parents=True, exist_ok=True)
                for path in (events_path, diagnostic_path, backend_path):
                    if path.exists():
                        shutil.copy2(path, args.output_dir / path.name)
            return 0
        except BaseException:
            if args.output_dir is not None:
                args.output_dir.mkdir(parents=True, exist_ok=True)
                for path in (events_path, diagnostic_path, backend_path):
                    if path.exists():
                        shutil.copy2(path, args.output_dir / path.name)
                for namespace, label in ((router, "router"), (client, "client")):
                    if namespace not in namespaces:
                        continue
                    state = run(
                        ns(namespace, "ip", "-6", "address", "show"),
                        check=False,
                    ).stdout
                    routes = run(
                        ns(namespace, "ip", "-6", "route", "show", "table", "all"),
                        check=False,
                    ).stdout
                    (args.output_dir / f"{label}-network.txt").write_text(
                        state + "\n" + routes,
                        encoding="utf-8",
                    )
            raise
        finally:
            stop(tcpcc)
            stop(backend)
            for namespace in reversed(namespaces):
                run(["ip", "netns", "delete", namespace], check=False)


def main() -> int:
    args = parse_args()
    if args.backend_server:
        return backend_server()
    if args.ipv6_client:
        return ipv6_client()
    if args.integration:
        return integration(args)
    raise ValueError("select --integration, --backend-server, or --ipv6-client")


if __name__ == "__main__":
    raise SystemExit(main())

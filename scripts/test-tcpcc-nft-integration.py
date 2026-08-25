#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Privileged namespace proof for exact nftables DNAT over real TUN queues."""

from __future__ import annotations

import argparse
import errno
import json
import os
import secrets
import select
import selectors
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from tcpcc_host import (  # noqa: E402
    NftDnatConfig,
    OwnershipJournal,
    TunConfig,
    create_tun_queue,
    install_nft_dnat,
)

PUBLIC_ADDRESS = "192.0.2.1"
CLIENT_ADDRESS = "192.0.2.2"
CLIENT_PREFIX = "192.0.2.0/24"
PUBLIC_PORT = 18443
ROUTER_TUN_ADDRESS = "198.18.0.1"
HOSTED_ADDRESS = "198.18.0.2"
HOSTED_PORT = 28443
TUN_MTU = 1460
PAYLOAD = b"tcpcc exact DNAT over two nonpersistent TUN queues"
REPLY_PREFIX = b"hosted-reply:"
KEEP_TABLE = "tcpcc_keep"
WORKER_TIMEOUT = 20.0


def _run(
    argv: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    timeout: float = WORKER_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        input=input_text,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def _netns_argv(namespace: str, argv: list[str]) -> list[str]:
    return ["ip", "netns", "exec", namespace, *argv]


def _write_tun_packet(fd: int, packet: bytes) -> None:
    while True:
        try:
            written = os.write(fd, packet)
        except BlockingIOError:
            _, writable, _ = select.select([], [fd], [], 1.0)
            if not writable:
                raise TimeoutError("TUN queue remained non-writable")
            continue
        if written != len(packet):
            raise RuntimeError(
                f"partial TUN packet write: {written}/{len(packet)} bytes"
            )
        return


def _relay_packets(tun_fd: int, relay: socket.socket) -> None:
    control_fd = sys.stdin.fileno()
    relay_fd = relay.fileno()
    while True:
        readable, _, _ = select.select(
            [tun_fd, relay_fd, control_fd],
            [],
            [],
            1.0,
        )
        if control_fd in readable:
            os.read(control_fd, 4096)
            return
        if tun_fd in readable:
            packet = os.read(tun_fd, 65535)
            if not packet:
                return
            relay.send(packet)
        if relay_fd in readable:
            packet = relay.recv(65535)
            if not packet:
                return
            _write_tun_packet(tun_fd, packet)


def _print_ready(**fields: object) -> None:
    print(
        json.dumps(
            {"status": "ready", **fields},
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )


def run_router_worker(relay_fd: int) -> None:
    relay = socket.socket(fileno=relay_fd)
    journal = OwnershipJournal()
    try:
        queue = create_tun_queue(
            TunConfig(
                host_address=ROUTER_TUN_ADDRESS,
                guest_address=HOSTED_ADDRESS,
                mtu=TUN_MTU,
            )
        )
        journal.defer(f"tun:{queue.name}", queue.close)
        dnat = install_nft_dnat(
            NftDnatConfig(
                listen_address=PUBLIC_ADDRESS,
                listen_port=PUBLIC_PORT,
                target_address=HOSTED_ADDRESS,
                target_port=HOSTED_PORT,
            )
        )
        journal.defer(f"nft:{dnat.table_name}", dnat.close)
        _print_ready(tun=queue.name, table=dnat.table_name)
        _relay_packets(queue.fd, relay)
    finally:
        relay.close()
        journal.close()


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        chunk = connection.recv(size - len(received))
        if not chunk:
            raise EOFError(f"TCP EOF after {len(received)}/{size} bytes")
        received.extend(chunk)
    return bytes(received)


def _serve_once(
    listener: socket.socket,
    stop: threading.Event,
    result: dict[str, BaseException | bool],
) -> None:
    try:
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(5.0)
                request = _recv_exact(connection, len(PAYLOAD))
                if request != PAYLOAD:
                    raise RuntimeError("hosted TCP request payload mismatch")
                connection.sendall(REPLY_PREFIX + request)
                connection.shutdown(socket.SHUT_WR)
                if connection.recv(1):
                    raise RuntimeError("hosted TCP received trailing payload")
            result["complete"] = True
            return
        raise RuntimeError("hosted TCP server stopped before accepting a flow")
    except BaseException as error:
        result["error"] = error


def run_hosted_worker(relay_fd: int) -> None:
    relay = socket.socket(fileno=relay_fd)
    journal = OwnershipJournal()
    listener: socket.socket | None = None
    server: threading.Thread | None = None
    stop = threading.Event()
    result: dict[str, BaseException | bool] = {}
    worker_error: BaseException | None = None
    try:
        queue = create_tun_queue(
            TunConfig(
                host_address=HOSTED_ADDRESS,
                guest_address=ROUTER_TUN_ADDRESS,
                mtu=TUN_MTU,
            )
        )
        journal.defer(f"tun:{queue.name}", queue.close)
        _run(
            [
                "ip",
                "route",
                "add",
                CLIENT_PREFIX,
                "via",
                ROUTER_TUN_ADDRESS,
                "dev",
                queue.name,
            ]
        )
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((HOSTED_ADDRESS, HOSTED_PORT))
        listener.listen(1)
        server = threading.Thread(
            target=_serve_once,
            args=(listener, stop, result),
            daemon=True,
        )
        server.start()
        _print_ready(tun=queue.name)
        _relay_packets(queue.fd, relay)
    except BaseException as error:
        worker_error = error
    finally:
        stop.set()
        if listener is not None:
            listener.close()
        if server is not None:
            server.join(timeout=5.0)
            if server.is_alive() and worker_error is None:
                worker_error = TimeoutError("hosted TCP server did not stop")
        relay.close()
        try:
            journal.close()
        except BaseException as error:
            if worker_error is None:
                worker_error = error
            else:
                worker_error = RuntimeError(
                    f"worker failed and cleanup also failed: {error}"
                )

    server_error = result.get("error")
    if worker_error is not None:
        raise worker_error
    if isinstance(server_error, BaseException):
        raise server_error
    if result.get("complete") is not True:
        raise RuntimeError("hosted TCP server did not complete one flow")


def run_client() -> None:
    expected = REPLY_PREFIX + PAYLOAD
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(10.0)
        connection.connect((PUBLIC_ADDRESS, PUBLIC_PORT))
        peer = connection.getpeername()
        connection.sendall(PAYLOAD)
        connection.shutdown(socket.SHUT_WR)
        reply = _recv_exact(connection, len(expected))
        if reply != expected:
            raise RuntimeError("client TCP reply payload mismatch")
        if connection.recv(1):
            raise RuntimeError("client received trailing reply payload")
    print(
        json.dumps(
            {
                "peer_address": peer[0],
                "peer_port": peer[1],
                "reply_bytes": len(reply),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def run_collision_probe() -> None:
    try:
        install_nft_dnat(
            NftDnatConfig(
                listen_address=PUBLIC_ADDRESS,
                listen_port=PUBLIC_PORT,
                target_address=HOSTED_ADDRESS,
                target_port=HOSTED_PORT,
                table_name=KEEP_TABLE,
            )
        )
    except subprocess.CalledProcessError as error:
        print(
            json.dumps(
                {
                    "existing_table_rejected": True,
                    "returncode": error.returncode,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return
    raise AssertionError(f"existing nftables table was adopted: {KEEP_TABLE}")


def _wait_ready(
    process: subprocess.Popen[str],
    label: str,
) -> dict[str, object]:
    if process.stdout is None:
        raise RuntimeError(f"{label} worker has no stdout pipe")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        if not selector.select(WORKER_TIMEOUT):
            raise TimeoutError(f"{label} worker did not report readiness")
        line = process.stdout.readline()
    finally:
        selector.close()
    if not line:
        try:
            _, stderr = process.communicate(timeout=1.0)
        except subprocess.TimeoutExpired:
            stderr = "worker still running without readiness output"
        raise RuntimeError(f"{label} worker exited before ready: {stderr}")
    report = json.loads(line)
    if report.get("status") != "ready":
        raise RuntimeError(f"invalid {label} readiness report: {line.rstrip()}")
    return report


def _stop_worker(process: subprocess.Popen[str], label: str) -> None:
    if process.stdin is not None and not process.stdin.closed:
        process.stdin.write("STOP\n")
        process.stdin.flush()
    try:
        _, stderr = process.communicate(timeout=WORKER_TIMEOUT)
    except subprocess.TimeoutExpired as error:
        raise TimeoutError(f"{label} worker did not stop") from error
    if process.returncode != 0:
        raise RuntimeError(
            f"{label} worker exited with {process.returncode}: {stderr}"
        )


def _force_stop(process: subprocess.Popen[str] | None) -> list[str]:
    errors: list[str] = []
    if process is None or process.poll() is not None:
        return errors
    try:
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.write("STOP\n")
            process.stdin.flush()
        process.communicate(timeout=2.0)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        process.terminate()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2.0)
    if process.poll() is None:
        errors.append(f"pid {process.pid} survived forced shutdown")
    return errors


def _counter_packets(document: dict[str, object]) -> int:
    maximum = 0
    for item in document.get("nftables", []):
        if not isinstance(item, dict):
            continue
        rule = item.get("rule")
        if not isinstance(rule, dict):
            continue
        expressions = rule.get("expr", [])
        if not isinstance(expressions, list):
            continue
        for expression in expressions:
            if not isinstance(expression, dict):
                continue
            counter = expression.get("counter")
            if isinstance(counter, dict):
                packets = counter.get("packets", 0)
                if isinstance(packets, int):
                    maximum = max(maximum, packets)
    return maximum


def _assert_conntrack_reverse(output: str) -> str:
    expected = (
        f"src={CLIENT_ADDRESS} dst={PUBLIC_ADDRESS}",
        f"dport={PUBLIC_PORT}",
        f"src={HOSTED_ADDRESS} dst={CLIENT_ADDRESS}",
        f"sport={HOSTED_PORT}",
    )
    for line in output.splitlines():
        if all(fragment in line for fragment in expected):
            return line
    raise AssertionError(
        "conntrack did not expose the expected original/reply NAT tuples: "
        f"{output}"
    )


def _namespace_names() -> tuple[str, str, str, str, str]:
    token = secrets.token_hex(3)
    pid = os.getpid()
    return (
        f"tccr-{pid}-{token}",
        f"tccc-{pid}-{token}",
        f"tcch-{pid}-{token}",
        f"tpr{token}",
        f"tpc{token}",
    )


def run_privileged_integration() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("nftables namespace integration must run as root")
    if not Path("/dev/net/tun").is_char_device():
        raise RuntimeError("/dev/net/tun is not an available character device")
    for command in ("ip", "nft", "conntrack", "sysctl"):
        if shutil.which(command) is None:
            raise RuntimeError(f"required integration command is missing: {command}")

    router_ns, client_ns, hosted_ns, router_veth, client_veth = (
        _namespace_names()
    )
    namespaces: list[str] = []
    router_process: subprocess.Popen[str] | None = None
    hosted_process: subprocess.Popen[str] | None = None
    relay_router: socket.socket | None = None
    relay_hosted: socket.socket | None = None
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    final_report: dict[str, object] | None = None

    try:
        for namespace in (router_ns, client_ns, hosted_ns):
            _run(["ip", "netns", "add", namespace])
            namespaces.append(namespace)

        _run(
            [
                "ip",
                "link",
                "add",
                router_veth,
                "type",
                "veth",
                "peer",
                "name",
                client_veth,
            ]
        )
        _run(["ip", "link", "set", router_veth, "netns", router_ns])
        _run(["ip", "link", "set", client_veth, "netns", client_ns])

        for namespace in (router_ns, client_ns, hosted_ns):
            _run(["ip", "-n", namespace, "link", "set", "lo", "up"])
        _run(
            [
                "ip",
                "-n",
                router_ns,
                "address",
                "add",
                f"{PUBLIC_ADDRESS}/24",
                "dev",
                router_veth,
            ]
        )
        _run(["ip", "-n", router_ns, "link", "set", router_veth, "up"])
        _run(
            [
                "ip",
                "-n",
                client_ns,
                "address",
                "add",
                f"{CLIENT_ADDRESS}/24",
                "dev",
                client_veth,
            ]
        )
        _run(["ip", "-n", client_ns, "link", "set", client_veth, "up"])
        _run(
            [
                "ip",
                "-n",
                client_ns,
                "route",
                "add",
                "default",
                "via",
                PUBLIC_ADDRESS,
            ]
        )

        for namespace in (router_ns, hosted_ns):
            for setting in (
                "net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.default.rp_filter=0",
            ):
                _run(
                    _netns_argv(namespace, ["sysctl", "-q", "-w", setting])
                )
        _run(
            _netns_argv(
                router_ns,
                ["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"],
            )
        )

        keep_batch = (
            f"create table ip {KEEP_TABLE}\n"
            f"add chain ip {KEEP_TABLE} sentinel\n"
        )
        _run(
            _netns_argv(router_ns, ["nft", "--file", "-"]),
            input_text=keep_batch,
        )
        keep_before = _run(
            _netns_argv(router_ns, ["nft", "list", "table", "ip", KEEP_TABLE])
        ).stdout
        collision_report = json.loads(
            _run(
                _netns_argv(
                    router_ns,
                    [sys.executable, str(Path(__file__).resolve()), "--collision"],
                )
            ).stdout
        )
        if collision_report.get("existing_table_rejected") is not True:
            raise AssertionError(f"invalid collision report: {collision_report}")
        keep_after_collision = _run(
            _netns_argv(router_ns, ["nft", "list", "table", "ip", KEEP_TABLE])
        ).stdout
        if keep_after_collision != keep_before:
            raise AssertionError("exclusive create changed the existing table")

        relay_router, relay_hosted = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_DGRAM,
        )
        script = str(Path(__file__).resolve())
        router_process = subprocess.Popen(
            _netns_argv(
                router_ns,
                [
                    sys.executable,
                    script,
                    "--router-worker",
                    "--relay-fd",
                    str(relay_router.fileno()),
                ],
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            pass_fds=(relay_router.fileno(),),
        )
        hosted_process = subprocess.Popen(
            _netns_argv(
                hosted_ns,
                [
                    sys.executable,
                    script,
                    "--hosted-worker",
                    "--relay-fd",
                    str(relay_hosted.fileno()),
                ],
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            pass_fds=(relay_hosted.fileno(),),
        )
        relay_router.close()
        relay_router = None
        relay_hosted.close()
        relay_hosted = None

        hosted_ready = _wait_ready(hosted_process, "hosted")
        router_ready = _wait_ready(router_process, "router")
        router_tun = str(router_ready["tun"])
        hosted_tun = str(hosted_ready["tun"])
        owned_table = str(router_ready["table"])

        client_result = _run(
            _netns_argv(
                client_ns,
                [sys.executable, script, "--client"],
            )
        )
        client_report = json.loads(client_result.stdout)
        if client_report["peer_address"] != PUBLIC_ADDRESS:
            raise AssertionError(f"unexpected client peer: {client_report}")
        if client_report["peer_port"] != PUBLIC_PORT:
            raise AssertionError(f"unexpected client peer: {client_report}")

        conntrack = _run(
            _netns_argv(
                router_ns,
                ["conntrack", "-L", "-f", "ipv4", "-p", "tcp"],
            )
        ).stdout
        conntrack_line = _assert_conntrack_reverse(conntrack)
        nft_document = json.loads(
            _run(
                _netns_argv(
                    router_ns,
                    ["nft", "--json", "list", "table", "ip", owned_table],
                )
            ).stdout
        )
        packets = _counter_packets(nft_document)
        if packets < 1:
            raise AssertionError("exact DNAT rule counter did not observe the flow")

        _stop_worker(router_process, "router")
        _stop_worker(hosted_process, "hosted")

        if _run(
            _netns_argv(
                router_ns,
                ["nft", "list", "table", "ip", owned_table],
            ),
            check=False,
        ).returncode == 0:
            raise AssertionError(
                f"owned nftables table survived cleanup: {owned_table}"
            )
        if _run(
            ["ip", "-n", router_ns, "link", "show", "dev", router_tun],
            check=False,
        ).returncode == 0:
            raise AssertionError(f"router TUN survived cleanup: {router_tun}")
        if _run(
            ["ip", "-n", hosted_ns, "link", "show", "dev", hosted_tun],
            check=False,
        ).returncode == 0:
            raise AssertionError(f"hosted TUN survived cleanup: {hosted_tun}")

        keep_after = _run(
            _netns_argv(router_ns, ["nft", "list", "table", "ip", KEEP_TABLE])
        ).stdout
        if keep_after != keep_before:
            raise AssertionError("unrelated nftables table changed byte-for-byte")

        final_report = {
            "schema": "tcpcc.nft-dnat-integration.v1",
            "public_endpoint": f"{PUBLIC_ADDRESS}:{PUBLIC_PORT}",
            "hosted_endpoint": f"{HOSTED_ADDRESS}:{HOSTED_PORT}",
            "payload_round_trip": True,
            "conntrack_reverse_translation": True,
            "conntrack_entry": conntrack_line,
            "dnat_counter_packets": packets,
            "real_tun_relay": True,
            "owned_resources_removed": True,
            "existing_table_rejected": True,
            "unrelated_table_unchanged": True,
        }
    except BaseException as error:
        primary_error = error
    finally:
        cleanup_errors.extend(_force_stop(router_process))
        cleanup_errors.extend(_force_stop(hosted_process))
        for relay in (relay_router, relay_hosted):
            if relay is not None:
                relay.close()
        for link in (router_veth, client_veth):
            _run(["ip", "link", "delete", link], check=False)
        for namespace in reversed(namespaces):
            deleted = _run(["ip", "netns", "delete", namespace], check=False)
            if deleted.returncode != 0:
                cleanup_errors.append(
                    f"could not delete namespace {namespace}: {deleted.stderr.strip()}"
                )

    remaining = {
        line.split()[0]
        for line in _run(["ip", "netns", "list"]).stdout.splitlines()
        if line
    }
    leftovers = remaining.intersection({router_ns, client_ns, hosted_ns})
    if leftovers:
        cleanup_errors.append(f"namespaces survived cleanup: {sorted(leftovers)}")

    if primary_error is not None:
        if cleanup_errors:
            raise RuntimeError(
                "integration failed and cleanup was incomplete: "
                + "; ".join(cleanup_errors)
            ) from primary_error
        raise primary_error
    if cleanup_errors:
        raise RuntimeError("integration cleanup failed: " + "; ".join(cleanup_errors))
    if final_report is None:
        raise RuntimeError("integration produced no final report")
    print(json.dumps(final_report, sort_keys=True, separators=(",", ":")))


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--integration", action="store_true")
    mode.add_argument("--router-worker", action="store_true")
    mode.add_argument("--hosted-worker", action="store_true")
    mode.add_argument("--client", action="store_true")
    mode.add_argument("--collision", action="store_true")
    parser.add_argument("--relay-fd", type=int)
    arguments = parser.parse_args()

    if arguments.integration:
        run_privileged_integration()
    elif arguments.client:
        run_client()
    elif arguments.collision:
        run_collision_probe()
    elif arguments.relay_fd is None:
        parser.error("worker modes require --relay-fd")
    elif arguments.router_worker:
        run_router_worker(arguments.relay_fd)
    else:
        run_hosted_worker(arguments.relay_fd)


if __name__ == "__main__":
    main()

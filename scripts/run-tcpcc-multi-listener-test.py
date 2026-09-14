#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise two hosted listeners sharing one aggregate tcpcc service."""

import argparse
import importlib.util
import os
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path

BASE = Path(__file__).with_name("run-tcpcc-tun-test.py")
SPEC = importlib.util.spec_from_file_location("tcpcc_tun_test", BASE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {BASE}")

tun_test = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tun_test)
control = tun_test.control

PUBLIC_PORTS = (18474, 18475)
SERVICE_MAX_CONNECTIONS = 4
SERVICE_ACCEPT_BATCH = 4
OP_HELLO = 22
FEATURE_MULTI_LISTENER = 1 << 5
HELLO = struct.Struct("<IIIIII64s")


def require_multi_listener_capability(
    proc: subprocess.Popen,
    responses: bytearray,
) -> int:
    _, _, raw_hello = control.transact(
        proc,
        responses,
        OP_HELLO,
        control.request(OP_HELLO),
        {"length": HELLO.size},
    )
    (
        control_version,
        feature_bits,
        _session_limit,
        _bridge_buffer_limit,
        _bridge_total_buffer_limit,
        reserved,
        linux_release,
    ) = HELLO.unpack(raw_hello)
    if control_version != control.VERSION:
        raise RuntimeError(
            f"HELLO returned control version {control_version}, expected {control.VERSION}"
        )
    if reserved:
        raise RuntimeError(f"HELLO reserved field is nonzero: {reserved}")
    if not feature_bits & FEATURE_MULTI_LISTENER:
        raise RuntimeError(
            "HELLO did not advertise TCPCC_CONTROL_FEATURE_MULTI_LISTENER "
            f"(features=0x{feature_bits:08x})"
        )
    if not linux_release.split(b"\0", 1)[0]:
        raise RuntimeError("HELLO returned an empty Linux release")
    return feature_bits


def start_backend(payload: bytes) -> dict[str, object]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.settimeout(tun_test.HOST_DRAIN_TIMEOUT)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    result: dict[str, object] = {}
    ready = threading.Event()
    thread = threading.Thread(
        target=tun_test.bridge_backend_worker,
        args=(listener, payload, result, ready),
        daemon=True,
    )
    thread.start()
    return {
        "listener": listener,
        "port": listener.getsockname()[1],
        "result": result,
        "ready": ready,
        "thread": thread,
        "payload": payload,
    }


def add_listener(proc: subprocess.Popen, responses: bytearray,
                 public_port: int, backend_port: int) -> int:
    listener_handle, _, _ = control.transact(
        proc,
        responses,
        control.OP_SOCKET,
        control.request(control.OP_SOCKET),
    )
    owned = True
    try:
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
                tun_test.GUEST_IPV4_U32,
                public_port,
            ),
        )
        control.transact(
            proc,
            responses,
            control.OP_LISTEN,
            control.request(control.OP_LISTEN, listener_handle, 8),
        )
        config = tun_test.SERVICE_CONFIG.pack(
            control.LOOPBACK,
            backend_port,
            0,
            SERVICE_MAX_CONNECTIONS,
            SERVICE_ACCEPT_BATCH,
        )
        service_handle, _, _ = control.transact(
            proc,
            responses,
            tun_test.OP_SERVICE_START,
            control.request(
                tun_test.OP_SERVICE_START,
                listener_handle,
                data=config,
            ),
            {"handle": 1, "length": 0},
        )
        owned = False
        return service_handle
    finally:
        if owned:
            try:
                control.transact(
                    proc,
                    responses,
                    control.OP_CLOSE,
                    control.request(control.OP_CLOSE, listener_handle),
                )
            except Exception:
                pass


def finish_backend(backend: dict[str, object]) -> None:
    thread = backend["thread"]
    assert isinstance(thread, threading.Thread)
    thread.join(tun_test.HOST_DRAIN_TIMEOUT)
    if thread.is_alive():
        raise TimeoutError("multi-listener backend did not finish")
    result = backend["result"]
    payload = backend["payload"]
    assert isinstance(result, dict)
    assert isinstance(payload, bytes)
    if "error" in result:
        raise RuntimeError("multi-listener backend failed") from result["error"]
    if result.get("data") != payload:
        raise RuntimeError("multi-listener public-to-backend payload mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--tun-name", required=True)
    parser.add_argument("--boot-log", required=True, type=Path)
    parser.add_argument("--tcp-log", required=True, type=Path)
    args = parser.parse_args()

    payloads = (
        control.make_payload(b"tcpcc-multi-listener-a:", 32791),
        control.make_payload(b"tcpcc-multi-listener-b:", 49181),
    )
    backends = [start_backend(payload) for payload in payloads]
    clients: list[socket.socket] = []
    responses = bytearray()
    proc: subprocess.Popen | None = None
    tun_fd = -1
    service_handle: int | None = None
    feature_bits: int | None = None
    error: Exception | None = None
    log = ""

    try:
        tun_fd = tun_test.attach_tun_queue(args.tun_name)
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

        feature_bits = require_multi_listener_capability(proc, responses)

        ifindex, _, _ = control.transact(
            proc,
            responses,
            control.OP_L3_ATTACH,
            control.request(
                control.OP_L3_ATTACH,
                child_fd,
                tun_test.GUEST_IPV4_U32,
                tun_test.GUEST_PREFIX,
            ),
        )
        if ifindex <= 0:
            raise RuntimeError(f"multi-listener L3 attach returned {ifindex}")

        handles = []
        for public_port, backend in zip(PUBLIC_PORTS, backends):
            handles.append(
                add_listener(proc, responses, public_port, int(backend["port"]))
            )
        if handles != [1, 1]:
            raise RuntimeError(f"listeners returned different service handles: {handles}")
        service_handle = handles[0]

        for public_port in PUBLIC_PORTS:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(tun_test.HOST_DRAIN_TIMEOUT)
            client.bind((tun_test.HOST_IPV4, 0))
            client.connect((tun_test.GUEST_IPV4, public_port))
            clients.append(client)

        for index, backend in enumerate(backends):
            ready = backend["ready"]
            result = backend["result"]
            assert isinstance(ready, threading.Event)
            assert isinstance(result, dict)
            if not ready.wait(control.CONTROL_TIMEOUT):
                raise TimeoutError(f"listener {index} backend accept did not become ready")
            if "error" in result:
                raise RuntimeError(f"listener {index} backend accept failed") from result[
                    "error"
                ]

        # Both bridges are active before either payload completes. Distinct
        # payloads and backend listeners catch accidental reuse of listener 0's
        # forwarding target by listener 1.
        for client, payload in zip(clients, payloads):
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
        for index, (client, payload) in enumerate(zip(clients, payloads)):
            echoed = tun_test.recv_exact(client, len(payload))
            if echoed != payload:
                raise RuntimeError(f"listener {index} backend-to-public payload mismatch")
            if client.recv(1):
                raise RuntimeError(f"listener {index} public connection missed EOF")

        for backend in backends:
            finish_backend(backend)

        _, _, raw_stats = control.transact(
            proc,
            responses,
            tun_test.OP_SERVICE_DRAIN,
            control.request(tun_test.OP_SERVICE_DRAIN, service_handle, 5000),
            {"length": tun_test.SERVICE_STATS.size},
        )
        drain_stats = tun_test.decode_service_stats(
            raw_stats, tun_test.SERVICE_DRAINING
        )
        _, _, observed_raw = control.transact(
            proc,
            responses,
            tun_test.OP_SERVICE_STATS,
            control.request(tun_test.OP_SERVICE_STATS, service_handle),
            {"length": tun_test.SERVICE_STATS.size},
        )
        if tun_test.decode_service_stats(
            observed_raw, tun_test.SERVICE_DRAINING
        ) != drain_stats:
            raise RuntimeError("aggregate stats changed after completed drain")

        _, _, raw_stats = control.transact(
            proc,
            responses,
            tun_test.OP_SERVICE_STOP,
            control.request(tun_test.OP_SERVICE_STOP, service_handle, 5000),
            {"length": tun_test.SERVICE_STATS.size},
        )
        stop_stats = tun_test.decode_service_stats(raw_stats, tun_test.SERVICE_STOPPED)
        service_handle = None
        (accepted, completed, rejected, public_to_backend, backend_to_public,
         active, peak, maximum, accept_batch, _accept_eagain, bridge_failures,
         terminal_failures, _state, last_error, *_reserved) = stop_stats
        total_bytes = sum(map(len, payloads))
        if (
            accepted != 2
            or completed != 2
            or rejected
            or public_to_backend != total_bytes
            or backend_to_public != total_bytes
            or active
            or peak != 2
            or maximum != SERVICE_MAX_CONNECTIONS
            or accept_batch != SERVICE_ACCEPT_BATCH
            or bridge_failures
            or terminal_failures
            or last_error
        ):
            raise RuntimeError(f"unexpected aggregate multi-listener stats {stop_stats}")

        assert feature_bits is not None
        log = (
            "hosted-multi-listener: hello=multi-listener "
            f"features=0x{feature_bits:08x} handles=1,1 routing=isolated "
            f"accepted={accepted} completed={completed} peak={peak} "
            f"public_to_backend={public_to_backend} "
            f"backend_to_public={backend_to_public} drain=aggregate stop=aggregate"
        )
        control.transact(proc, responses, control.OP_FINISH, control.request(control.OP_FINISH))
        try:
            returncode = proc.wait(timeout=control.CONTROL_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("multi-listener kernel did not reach final boundary") from exc
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
        for client in clients:
            client.close()
        for backend in backends:
            listener = backend["listener"]
            assert isinstance(listener, socket.socket)
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
        args.boot_log.write_bytes(stderr)
        args.tcp_log.write_text(log + ("\n" if log else ""), encoding="utf-8")

    if error is not None:
        print(f"hosted multi-listener test failed: {error}", file=sys.stderr)
        return 1
    print(log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
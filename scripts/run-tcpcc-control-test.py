#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import argparse
import struct
import subprocess
import sys
from pathlib import Path

MAGIC = 0x32434354
VERSION = 1
MAX_PAYLOAD = 256
LOOPBACK = 0x7F000001
PORT = 41042

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

REQUEST = struct.Struct("<IHHiIII256s")
RESPONSE = struct.Struct("<IHHiiI256s")


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--boot-log", required=True, type=Path)
    parser.add_argument("--responses", required=True, type=Path)
    args = parser.parse_args()

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
        (OP_FINISH, request(OP_FINISH), {}),
    ]

    input_bytes = b"".join(encoded for _, encoded, _ in commands)
    try:
        completed = subprocess.run(
            [str(args.kernel)],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        args.boot_log.parent.mkdir(parents=True, exist_ok=True)
        args.boot_log.write_bytes(exc.stderr or b"")
        print("hosted M4.2 control test timed out", file=sys.stderr)
        return 1

    args.boot_log.parent.mkdir(parents=True, exist_ok=True)
    args.boot_log.write_bytes(completed.stderr)
    args.responses.write_bytes(completed.stdout)

    if completed.returncode != 86:
        print(f"expected hosted kernel exit status 86, got {completed.returncode}",
              file=sys.stderr)
        return 1

    expected_size = len(commands) * RESPONSE.size
    if len(completed.stdout) != expected_size:
        print(
            f"expected {expected_size} response bytes, got {len(completed.stdout)}",
            file=sys.stderr,
        )
        return 1

    for index, (expected_op, _, expectation) in enumerate(commands):
        offset = index * RESPONSE.size
        fields = RESPONSE.unpack_from(completed.stdout, offset)
        magic, version, op, status, handle, length, raw_data = fields

        if magic != MAGIC or version != VERSION or op != expected_op:
            print(
                f"response {index} header mismatch: magic=0x{magic:08x} "
                f"version={version} op={op}",
                file=sys.stderr,
            )
            return 1
        if status != 0:
            print(f"response {index} op {op} failed with {status}", file=sys.stderr)
            return 1
        if "handle" in expectation and handle != expectation["handle"]:
            print(
                f"response {index} expected handle {expectation['handle']}, got {handle}",
                file=sys.stderr,
            )
            return 1
        if "length" in expectation and length != expectation["length"]:
            print(
                f"response {index} expected length {expectation['length']}, got {length}",
                file=sys.stderr,
            )
            return 1
        if "data" in expectation:
            expected_data = expectation["data"]
            if length != len(expected_data) or raw_data[:length] != expected_data:
                print(f"response {index} payload mismatch", file=sys.stderr)
                return 1

    print(
        "M4.2 host control protocol passed: socket/bind/listen/connect/accept, "
        "bidirectional I/O, close, Reno and CUBIC"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

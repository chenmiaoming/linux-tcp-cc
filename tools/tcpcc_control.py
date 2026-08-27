#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Strict userspace client for the ARCH=tcpcc hosted control ABI."""

from __future__ import annotations

import os
import select
import struct
import time
from dataclasses import dataclass
from typing import BinaryIO, Callable

MAGIC = 0x32434354
VERSION = 1
MAX_PAYLOAD = 256
CONTROL_TIMEOUT = 8.0

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
OP_TCP_INFO = 14
OP_HOST_BACKEND_PROBE = 15
OP_BRIDGE_START = 16
OP_BRIDGE_JOIN = 17
OP_BRIDGE_CANCEL = 18
OP_ACCEPT_NONBLOCK = 19
OP_SHUTDOWN = 20
OP_BRIDGE_JOIN_RESULT = 21
OP_HELLO = 22

OP_NAMES = {
    OP_SOCKET: "socket",
    OP_BIND: "bind",
    OP_LISTEN: "listen",
    OP_CONNECT: "connect",
    OP_ACCEPT: "accept",
    OP_WRITE: "write",
    OP_READ: "read",
    OP_CLOSE: "close",
    OP_SET_CC: "set-cc",
    OP_GET_CC: "get-cc",
    OP_FINISH: "finish",
    OP_L3_ATTACH: "l3-attach",
    OP_L3_STATS: "l3-stats",
    OP_TCP_INFO: "tcp-info",
    OP_HOST_BACKEND_PROBE: "host-backend-probe",
    OP_BRIDGE_START: "bridge-start",
    OP_BRIDGE_JOIN: "bridge-join",
    OP_BRIDGE_CANCEL: "bridge-cancel",
    OP_ACCEPT_NONBLOCK: "accept-nonblock",
    OP_SHUTDOWN: "shutdown",
    OP_BRIDGE_JOIN_RESULT: "bridge-join-result",
    OP_HELLO: "hello",
}

REQUEST = struct.Struct("<IHHiIII256s")
RESPONSE = struct.Struct("<IHHiiI256s")
BRIDGE_RESULT = struct.Struct("<QQQIIIIIIIiII")


class ControlError(RuntimeError):
    """Base class for hosted control failures."""


class ControlProtocolError(ControlError):
    """The hosted process returned a malformed or mismatched record."""


class ControlOperationError(ControlError):
    """One well-formed hosted operation returned a non-allowed status."""

    def __init__(self, operation: int, status: int) -> None:
        self.operation = operation
        self.status = status
        name = OP_NAMES.get(operation, f"op-{operation}")
        if status < 0:
            try:
                detail = os.strerror(-status)
            except ValueError:
                detail = "unknown errno"
        else:
            detail = "unexpected non-negative status"
        super().__init__(f"hosted {name} failed with status {status}: {detail}")


@dataclass(frozen=True)
class ControlResponse:
    operation: int
    status: int
    handle: int
    data: bytes


@dataclass(frozen=True)
class BridgeResult:
    token: int
    public_to_backend_bytes: int
    backend_to_public_bytes: int
    buffer_limit: int
    total_buffer_limit: int
    terminal_events: int
    host_send_eagain: int
    host_partial_writes: int
    host_recv_eagain: int
    session_limit: int
    status: int


def _bounded_integer(
    value: int,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{field} must be from {minimum} through {maximum}")
    return value


def encode_request(
    operation: int,
    handle: int = 0,
    arg0: int = 0,
    arg1: int = 0,
    data: bytes = b"",
) -> bytes:
    """Encode one fixed-size version-1 request after validating every field."""

    _bounded_integer(operation, "operation", 1, 0xFFFF)
    _bounded_integer(handle, "handle", -(1 << 31), (1 << 31) - 1)
    _bounded_integer(arg0, "arg0", 0, 0xFFFFFFFF)
    _bounded_integer(arg1, "arg1", 0, 0xFFFFFFFF)
    if not isinstance(data, bytes):
        raise TypeError("control data must be bytes")
    if len(data) > MAX_PAYLOAD:
        raise ValueError(f"control data exceeds the {MAX_PAYLOAD}-byte ABI limit")
    return REQUEST.pack(
        MAGIC,
        VERSION,
        operation,
        handle,
        arg0,
        arg1,
        len(data),
        data.ljust(MAX_PAYLOAD, b"\0"),
    )


def decode_response(raw: bytes, expected_operation: int) -> ControlResponse:
    """Decode one complete response and reject ABI drift or corruption."""

    if not isinstance(raw, bytes) or len(raw) != RESPONSE.size:
        length = len(raw) if isinstance(raw, bytes) else "non-bytes"
        raise ControlProtocolError(
            f"control response has size {length}, expected {RESPONSE.size}"
        )
    (
        magic,
        version,
        operation,
        status,
        handle,
        length,
        payload,
    ) = RESPONSE.unpack(raw)
    if magic != MAGIC:
        raise ControlProtocolError(f"control response magic is 0x{magic:08x}")
    if version != VERSION:
        raise ControlProtocolError(
            f"control response version is {version}, expected {VERSION}"
        )
    if operation != expected_operation:
        raise ControlProtocolError(
            f"control response operation is {operation}, "
            f"expected {expected_operation}"
        )
    if length > MAX_PAYLOAD:
        raise ControlProtocolError(
            f"control response payload is {length} bytes, maximum is {MAX_PAYLOAD}"
        )
    return ControlResponse(operation, status, handle, payload[:length])


def decode_bridge_result(
    data: bytes,
    *,
    allow_terminal_error: bool = False,
) -> BridgeResult:
    """Decode and validate the stable 64-byte bridge completion snapshot."""

    if not isinstance(data, bytes) or len(data) != BRIDGE_RESULT.size:
        length = len(data) if isinstance(data, bytes) else "non-bytes"
        raise ControlProtocolError(
            f"bridge result has size {length}, expected {BRIDGE_RESULT.size}"
        )
    (
        token,
        public_to_backend,
        backend_to_public,
        buffer_limit,
        total_buffer_limit,
        terminal_events,
        host_send_eagain,
        host_partial_writes,
        host_recv_eagain,
        session_limit,
        status,
        reserved0,
        reserved1,
    ) = BRIDGE_RESULT.unpack(data)
    if reserved0 or reserved1:
        raise ControlProtocolError(
            f"bridge result reserved fields are {reserved0}/{reserved1}"
        )
    if status and not allow_terminal_error:
        raise ControlProtocolError(
            f"successful bridge response contains status {status}"
        )
    if status > 0:
        raise ControlProtocolError(
            f"bridge result contains positive terminal status {status}"
        )
    if session_limit < 1:
        raise ControlProtocolError("bridge result reports a zero session limit")
    return BridgeResult(
        token,
        public_to_backend,
        backend_to_public,
        buffer_limit,
        total_buffer_limit,
        terminal_events,
        host_send_eagain,
        host_partial_writes,
        host_recv_eagain,
        session_limit,
        status,
    )


def read_exact_fd(
    fd: int,
    length: int,
    timeout: float,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> bytes:
    """Read exactly one record with a single overall timeout."""

    _bounded_integer(fd, "fd", 0, (1 << 31) - 1)
    _bounded_integer(length, "length", 1, (1 << 31) - 1)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a number")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    deadline = clock() + timeout
    result = bytearray()
    while len(result) < length:
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError(
                f"hosted control response timed out after "
                f"{len(result)}/{length} bytes"
            )
        readable, _writable, _exceptional = select.select(
            [fd],
            [],
            [],
            remaining,
        )
        if not readable:
            raise TimeoutError(
                f"hosted control response timed out after "
                f"{len(result)}/{length} bytes"
            )
        chunk = os.read(fd, length - len(result))
        if not chunk:
            raise EOFError(
                f"hosted control response reached EOF after "
                f"{len(result)}/{length} bytes"
            )
        result.extend(chunk)
    return bytes(result)


class ControlClient:
    """Serialize requests over one hosted process's stdin/stdout pipes."""

    def __init__(
        self,
        stdin: BinaryIO,
        stdout: BinaryIO,
        *,
        timeout: float = CONTROL_TIMEOUT,
    ) -> None:
        if stdin is None or stdout is None:
            raise ValueError("hosted control pipes are unavailable")
        if timeout <= 0:
            raise ValueError("control timeout must be positive")
        self._stdin = stdin
        self._stdout = stdout
        self.timeout = timeout

    def transact(
        self,
        operation: int,
        handle: int = 0,
        arg0: int = 0,
        arg1: int = 0,
        data: bytes = b"",
        *,
        allowed_statuses: tuple[int, ...] = (0,),
    ) -> ControlResponse:
        if not allowed_statuses:
            raise ValueError("allowed_statuses must not be empty")
        encoded = encode_request(operation, handle, arg0, arg1, data)
        try:
            written = self._stdin.write(encoded)
            if written is not None and written != len(encoded):
                raise BrokenPipeError(
                    f"short control write: {written}/{len(encoded)} bytes"
                )
            self._stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as error:
            name = OP_NAMES.get(operation, f"op-{operation}")
            raise ControlError(f"could not send hosted {name} request: {error}") from error

        raw = read_exact_fd(self._stdout.fileno(), RESPONSE.size, self.timeout)
        response = decode_response(raw, operation)
        if response.status not in allowed_statuses:
            raise ControlOperationError(operation, response.status)
        return response

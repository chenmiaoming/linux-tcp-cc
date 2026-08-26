#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prove M8.4 nonblocking accept and clean hosted shutdown without root."""

from __future__ import annotations

import argparse
import errno
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from tcpcc_control import (  # noqa: E402
    OP_ACCEPT_NONBLOCK,
    OP_BIND,
    OP_CLOSE,
    OP_GET_CC,
    OP_L3_ATTACH,
    OP_LISTEN,
    OP_SET_CC,
    OP_SHUTDOWN,
    OP_SOCKET,
    ControlClient,
    ControlOperationError,
)

GUEST_ADDRESS = 0xC0000202
GUEST_PREFIX = 32
LISTEN_PORT = 18453
EXPECTED_LOGS = (
    "tcpcc: M8.4 default IPv4 route active on tcpcc0",
    "tcpcc: M8.4 hosted runtime stopped cleanly",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--boot-log", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    host_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    child_fd = child_socket.fileno()
    process = subprocess.Popen(
        [str(args.kernel)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(child_fd,),
        bufsize=0,
        start_new_session=True,
    )
    child_socket.close()
    error: BaseException | None = None
    listener = 0

    try:
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("hosted process did not expose control pipes")
        control = ControlClient(process.stdin, process.stdout)
        attached = control.transact(
            OP_L3_ATTACH,
            child_fd,
            GUEST_ADDRESS,
            GUEST_PREFIX,
        )
        if attached.handle <= 0:
            raise RuntimeError(f"invalid hosted ifindex {attached.handle}")

        listener = control.transact(OP_SOCKET).handle
        control.transact(OP_SET_CC, listener, data=b"bbr")
        observed = control.transact(OP_GET_CC, listener).data
        if observed != b"bbr":
            raise RuntimeError(f"listener CC is {observed!r}, expected b'bbr'")
        control.transact(OP_BIND, listener, GUEST_ADDRESS, LISTEN_PORT)
        control.transact(OP_LISTEN, listener, 8)
        try:
            control.transact(OP_ACCEPT_NONBLOCK, listener)
        except ControlOperationError as accept_error:
            if accept_error.status != -errno.EAGAIN:
                raise
        else:
            raise RuntimeError("nonblocking accept unexpectedly returned a socket")

        control.transact(OP_CLOSE, listener)
        listener = 0
        control.transact(OP_SHUTDOWN)
        status = process.wait(timeout=10)
        if status != 0:
            raise RuntimeError(f"clean hosted shutdown returned status {status}")
    except BaseException as caught:
        error = caught
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    finally:
        host_socket.close()
        if process.stdin is not None:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
        if process.stdout is not None:
            process.stdout.close()
        stderr = process.stderr.read() if process.stderr is not None else b""
        args.boot_log.parent.mkdir(parents=True, exist_ok=True)
        args.boot_log.write_bytes(stderr)

    if error is not None:
        print(f"M8.4 hosted runtime test failed: {error}", file=sys.stderr)
        return 1
    decoded = stderr.decode("utf-8", errors="replace")
    for expected in EXPECTED_LOGS:
        if expected not in decoded:
            print(f"M8.4 hosted runtime log is missing: {expected}", file=sys.stderr)
            return 1
    if "Kernel panic" in decoded:
        print("M8.4 clean shutdown unexpectedly panicked", file=sys.stderr)
        return 1
    print(
        "M8.4 hosted runtime passed: nonblocking accept returned EAGAIN, "
        "listener selected BBR, and SHUTDOWN exited 0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

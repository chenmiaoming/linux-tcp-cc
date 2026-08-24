#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""M6.1 hosted BBR selection plus the existing M5 packet-path diagnostics."""
import importlib.util
import socket
from pathlib import Path

BASE = Path(__file__).with_name("run-tcpcc-control-test.py")
SPEC = importlib.util.spec_from_file_location("tcpcc_control_test", BASE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {BASE}")

control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)
_original_exercise_l3 = control.exercise_l3


def exercise_m6_control(proc, responses):
    client_payload = control.make_payload(b"tcpcc-m6.1-client-to-server:", 192)
    server_payload = control.make_payload(b"tcpcc-m6.1-server-to-client:", 224)

    commands = [
        (control.OP_SOCKET, control.request(control.OP_SOCKET), {"handle": 1}),
        (control.OP_BIND,
         control.request(control.OP_BIND, 1, control.LOOPBACK, control.PORT), {}),
        (control.OP_LISTEN, control.request(control.OP_LISTEN, 1, 8), {}),
        (control.OP_SOCKET, control.request(control.OP_SOCKET), {"handle": 2}),
        (control.OP_SET_CC,
         control.request(control.OP_SET_CC, 2, data=b"reno"), {}),
        (control.OP_GET_CC,
         control.request(control.OP_GET_CC, 2), {"data": b"reno"}),
        (control.OP_SET_CC,
         control.request(control.OP_SET_CC, 2, data=b"cubic"), {}),
        (control.OP_GET_CC,
         control.request(control.OP_GET_CC, 2), {"data": b"cubic"}),
        (control.OP_SET_CC,
         control.request(control.OP_SET_CC, 2, data=b"bbr"), {}),
        (control.OP_GET_CC,
         control.request(control.OP_GET_CC, 2), {"data": b"bbr"}),
        (control.OP_CONNECT,
         control.request(control.OP_CONNECT, 2, control.LOOPBACK, control.PORT), {}),
        (control.OP_ACCEPT, control.request(control.OP_ACCEPT, 1), {"handle": 3}),
        (control.OP_WRITE, control.request(control.OP_WRITE, 2, data=client_payload),
         {"length": len(client_payload)}),
        (control.OP_READ, control.request(control.OP_READ, 3, len(client_payload)),
         {"data": client_payload}),
        (control.OP_WRITE, control.request(control.OP_WRITE, 3, data=server_payload),
         {"length": len(server_payload)}),
        (control.OP_READ, control.request(control.OP_READ, 2, len(server_payload)),
         {"data": server_payload}),
        (control.OP_CLOSE, control.request(control.OP_CLOSE, 3), {}),
        (control.OP_CLOSE, control.request(control.OP_CLOSE, 2), {}),
        (control.OP_CLOSE, control.request(control.OP_CLOSE, 1), {}),
    ]

    for op, encoded, expectation in commands:
        control.transact(proc, responses, op, encoded, expectation)


def diagnostic_exercise_l3(proc, responses, host_sock, child_fd):
    try:
        return _original_exercise_l3(proc, responses, host_sock, child_fd)
    except socket.timeout as exc:
        try:
            _, length, raw_stats = control.transact(
                proc,
                responses,
                control.OP_L3_STATS,
                control.request(control.OP_L3_STATS),
            )
            if length != control.L3_STATS.size:
                raise RuntimeError(
                    f"L3 stats size mismatch: {length} != {control.L3_STATS.size}"
                )
            stats = control.L3_STATS.unpack(raw_stats)
        except Exception as stats_exc:
            raise TimeoutError(
                f"ICMP receive timed out; follow-up L3 stats query failed: {stats_exc}"
            ) from exc

        raise TimeoutError(
            "ICMP receive timed out with "
            f"rx_packets={stats[0]} rx_bytes={stats[1]} "
            f"rx_dropped={stats[2]} rx_errors={stats[3]} "
            f"tx_packets={stats[4]} tx_bytes={stats[5]} "
            f"tx_dropped={stats[6]} tx_errors={stats[7]}"
        ) from exc


control.exercise_m4_control = exercise_m6_control
control.exercise_l3 = diagnostic_exercise_l3
exit_code = control.main()
if exit_code == 0:
    print("M6.1 native TCP_CONGESTION selection passed: Reno, CUBIC, BBR; active loopback flow used BBR")
raise SystemExit(exit_code)

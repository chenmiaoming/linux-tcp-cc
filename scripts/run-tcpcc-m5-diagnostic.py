#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Temporary M5.1 diagnostic wrapper for the hosted packet-path test."""
import importlib.util
import socket
import sys
from pathlib import Path

BASE = Path(__file__).with_name("run-tcpcc-control-test.py")
SPEC = importlib.util.spec_from_file_location("tcpcc_control_test", BASE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {BASE}")

control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)
_original_exercise_l3 = control.exercise_l3


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


control.exercise_l3 = diagnostic_exercise_l3
raise SystemExit(control.main())

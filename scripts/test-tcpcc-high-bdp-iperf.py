#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Deterministic tests for the high-BDP iperf3 comparison contract."""

from __future__ import annotations

import copy
import errno
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/run-tcpcc-high-bdp-iperf.py"
SPEC = importlib.util.spec_from_file_location("tcpcc_high_bdp", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {SCRIPT}")
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


def scenario_document() -> dict[str, object]:
    return json.loads(
        (ROOT / "benchmarks/m8/iperf-high-bdp-loss-v1.json").read_text(
            encoding="utf-8"
        )
    )


def iperf_document(
    *,
    cc: str = "bbr",
    reverse: int = 1,
    bits_per_second: float = 40_000_000,
    retransmits: int = 12,
) -> dict[str, object]:
    return {
        "start": {
            "test_start": {
                "protocol": "TCP",
                "reverse": reverse,
                "num_streams": 1,
            }
        },
        "end": {
            "sum_sent": {
                "bits_per_second": bits_per_second,
                "bytes": 50_000_000,
                "seconds": 10.0,
                "retransmits": retransmits,
            },
            "sum_received": {
                "bits_per_second": bits_per_second,
                "bytes": 49_000_000,
                "seconds": 10.0,
            },
            "sender_tcp_congestion": cc,
            "receiver_tcp_congestion": cc,
        },
    }


class ScenarioTests(unittest.TestCase):
    def test_checked_scenario_derives_rtt_and_bdp(self) -> None:
        scenario = benchmark.parse_scenario(scenario_document())

        self.assertEqual(scenario.rtt_ms, 100)
        self.assertEqual(scenario.bdp_bytes, 625_000)
        self.assertEqual(scenario.repetitions, 3)
        self.assertGreater(
            scenario.netem_limit_packets * scenario.mtu,
            2 * scenario.bdp_bytes,
        )

    def test_scenario_rejects_parallel_or_undersized_queue(self) -> None:
        parallel = scenario_document()
        parallel["iperf"]["parallel_streams"] = 2  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "exactly 1"):
            benchmark.parse_scenario(parallel)

        queue = scenario_document()
        queue["network"]["netem_limit_packets"] = 100  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "two path BDPs"):
            benchmark.parse_scenario(queue)


class IperfParserTests(unittest.TestCase):
    def test_reverse_single_stream_exposes_delivered_goodput(self) -> None:
        result = benchmark.parse_iperf_document(
            iperf_document(),
            expected_sender_cc="bbr",
        )

        self.assertEqual(result["goodput_mbps"], 40.0)
        self.assertEqual(result["received_bytes"], 49_000_000)
        self.assertEqual(result["retransmits"], 12)
        self.assertEqual(result["sender_tcp_congestion"], "bbr")

    def test_forward_or_wrong_sender_cc_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "reverse"):
            benchmark.parse_iperf_document(
                iperf_document(reverse=0),
                expected_sender_cc="bbr",
            )
        with self.assertRaisesRegex(ValueError, "expected 'bbr'"):
            benchmark.parse_iperf_document(
                iperf_document(cc="cubic"),
                expected_sender_cc="bbr",
            )


class QdiscParserTests(unittest.TestCase):
    def test_netem_configuration_and_loss_counters_are_decoded(self) -> None:
        scenario = benchmark.parse_scenario(scenario_document())
        result = benchmark.parse_qdisc_document(
            [
                {
                    "kind": "netem",
                    "root": True,
                    "options": {
                        "limit": 20000,
                        "delay": {"delay": 0.05},
                        "loss-random": {"loss": 0.001},
                        "rate": {"rate": 6_250_000},
                    },
                    "bytes": 10_000_000,
                    "packets": 99_900,
                    "drops": 100,
                    "overlimits": 0,
                    "backlog": 0,
                }
            ],
            expected_kind="netem",
            scenario=scenario,
        )

        self.assertEqual(result["drops"], 100)
        self.assertEqual(result["observed_drop_percent"], 0.1)

    def test_netem_configuration_drift_is_rejected(self) -> None:
        scenario = benchmark.parse_scenario(scenario_document())
        with self.assertRaisesRegex(ValueError, "delay"):
            benchmark.parse_qdisc_document(
                [
                    {
                        "kind": "netem",
                        "root": True,
                        "options": {
                            "limit": 20000,
                            "delay": {"delay": 0.025},
                            "loss-random": {"loss": 0.001},
                            "rate": {"rate": 6_250_000},
                        },
                        "bytes": 0,
                        "packets": 0,
                        "drops": 0,
                        "overlimits": 0,
                        "backlog": 0,
                    }
                ],
                expected_kind="netem",
                scenario=scenario,
            )


class SummaryTests(unittest.TestCase):
    @staticmethod
    def runs(*values: float) -> list[dict[str, object]]:
        return [
            {"goodput_mbps": value, "retransmits": index + 1}
            for index, value in enumerate(values)
        ]

    def test_medians_and_comparisons_are_stable(self) -> None:
        scenario = benchmark.parse_scenario(scenario_document())
        summaries, checks, passed = benchmark.summarize_measurements(
            {
                "native_cubic": self.runs(9, 10, 11),
                "native_bbr": self.runs(39, 40, 41),
                "tcpcc_bbr": self.runs(35, 36, 37),
            },
            scenario,
        )

        self.assertTrue(passed)
        self.assertEqual(
            summaries["native_cubic"]["median_goodput_mbps"],
            10,
        )
        self.assertEqual(
            summaries["comparisons"]["native_bbr_over_native_cubic"],
            4,
        )
        self.assertEqual(
            summaries["comparisons"]["tcpcc_bbr_over_native_bbr"],
            0.9,
        )
        observations = [check for check in checks if not check["gate"]]
        self.assertEqual(len(observations), 2)

    def test_tcpcc_native_bbr_ratio_is_a_gate(self) -> None:
        document = copy.deepcopy(scenario_document())
        document["acceptance"][  # type: ignore[index]
            "tcpcc_to_native_bbr_min_ratio"
        ] = 0.8
        scenario = benchmark.parse_scenario(document)
        _summaries, checks, passed = benchmark.summarize_measurements(
            {
                "native_cubic": self.runs(9, 10, 11),
                "native_bbr": self.runs(39, 40, 41),
                "tcpcc_bbr": self.runs(19, 20, 21),
            },
            scenario,
        )

        self.assertFalse(passed)
        ratio = next(
            check for check in checks
            if check["name"] == "tcpcc_to_native_bbr_ratio"
        )
        self.assertTrue(ratio["gate"])
        self.assertFalse(ratio["passed"])


class TcpccEventTests(unittest.TestCase):
    @staticmethod
    def events(data_status: int) -> list[dict[str, object]]:
        return [
            {"event": "ready", "cc": "bbr"},
            {
                "event": "service-stats",
                "accepted_connections": 6,
                "completed_connections": 6,
                "active_connections": 0,
                "peak_connections": 2,
                "rejected_connections": 0,
                "bridge_start_failures": 0,
                "terminal_failures": 3 if data_status else 0,
                "last_error": data_status,
                "backend_to_public_bytes": 24_000_000,
            },
            {"event": "stopped", "clean": True},
        ]

    def test_iperf_abortive_data_close_is_recorded_not_failed(self) -> None:
        scenario = benchmark.parse_scenario(scenario_document())
        result = benchmark.validate_tcpcc_events(
            self.events(-errno.ECONNRESET),
            scenario,
        )

        self.assertEqual(result["completed_data_flows"], 3)
        self.assertEqual(result["completed_control_flows"], 3)
        self.assertEqual(result["terminal_statuses"][str(-errno.ECONNRESET)], 3)

    def test_cancellation_is_not_accepted_as_iperf_teardown(self) -> None:
        scenario = benchmark.parse_scenario(scenario_document())
        with self.assertRaisesRegex(RuntimeError, "unexpected terminal aggregate"):
            benchmark.validate_tcpcc_events(
                self.events(-errno.ECANCELED),
                scenario,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

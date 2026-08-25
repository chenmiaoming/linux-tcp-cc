#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("compare-m7-lossless.py")
SPEC = importlib.util.spec_from_file_location("compare_m7_lossless", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def thresholds() -> dict:
    return {
        "schema_version": 1,
        "scenario_id": "hosted-lossless-delayed-50ms",
        "parity_scenario_id": "lossless-delayed-50ms-v1",
        "runtime_metrics": {
            "rtt_us": {"min_ratio": 0.5, "max_ratio": 2.0, "gate": True},
            "snd_cwnd": {"min_ratio": 0.25, "max_ratio": 4.0, "gate": False},
        },
        "observation_metrics": ["lost", "retrans", "total_retrans"],
    }


def report(kind: str, *, rtt_us: int = 50000) -> dict:
    scenario = {
        "parity_scenario_id": "lossless-delayed-50ms-v1",
        "transfer": {
            "congestion_controls": ["cubic", "bbr"],
            "guest_to_host_bytes_per_cc": 2097152,
            "host_to_guest_bytes_per_cc": 16384,
        },
    }
    fields = {
        "guest_to_host": 2097152,
        "host_to_guest": 16384,
        "state": 1,
        "rtt_us": rtt_us,
        "snd_cwnd": 16,
        "lost": 0,
        "retrans": 0,
        "total_retrans": 0,
    }
    return {
        "schema_version": 1,
        "scenario_id": "hosted-lossless-delayed-50ms",
        "scenario": scenario,
        "runtime": {"kind": kind},
        "upstream": {"tag": "v6.18.45", "commit": "deadbeef"},
        "path": {"qdisc": {"dropped": 0}},
        "congestion_controls": {
            "cubic": dict(fields),
            "bbr": dict(fields),
        },
        "acceptance": {"passed": True},
    }


class CompareM7LosslessTests(unittest.TestCase):
    def test_matching_reports_pass(self) -> None:
        result = MOD.compare(report("native-linux"), report("tcpcc"), thresholds())
        self.assertEqual(result["status"], "pass")

    def test_upstream_mismatch_fails(self) -> None:
        native = report("native-linux")
        hosted = report("tcpcc")
        hosted["upstream"]["commit"] = "cafebabe"
        result = MOD.compare(native, hosted, thresholds())
        self.assertEqual(result["status"], "fail")
        self.assertFalse(result["correctness"]["passed"])

    def test_gated_rtt_ratio_fails(self) -> None:
        result = MOD.compare(
            report("native-linux", rtt_us=50000),
            report("tcpcc", rtt_us=150000),
            thresholds(),
        )
        self.assertEqual(result["status"], "fail")
        self.assertFalse(result["runtime_scheduling"]["passed"])

    def test_observation_metric_does_not_fail(self) -> None:
        native = report("native-linux")
        hosted = report("tcpcc")
        hosted["congestion_controls"]["bbr"]["total_retrans"] = 9
        result = MOD.compare(native, hosted, thresholds())
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["observations"]["loss_counters"]["bbr"]["total_retrans"]["hosted"], 9)

    def test_non_gated_metric_outside_tolerance_is_observed(self) -> None:
        native = report("native-linux")
        hosted = report("tcpcc")
        hosted["congestion_controls"]["cubic"]["snd_cwnd"] = 1000
        result = MOD.compare(native, hosted, thresholds())
        self.assertEqual(result["status"], "pass")
        check = next(
            item for item in result["runtime_scheduling"]["checks"]
            if item["name"] == "cubic_snd_cwnd_ratio"
        )
        self.assertFalse(check["gate"])
        self.assertFalse(check["passed"])


if __name__ == "__main__":
    unittest.main()

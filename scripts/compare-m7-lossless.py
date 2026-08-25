#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compare M7 lossless native Linux and tcpcc hosted reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return value


def add_check(checks: list[dict[str, Any]], name: str, passed: bool,
              observed: Any, expected: Any, *, gate: bool = True) -> None:
    checks.append({
        "name": name,
        "gate": bool(gate),
        "passed": bool(passed),
        "observed": observed,
        "expected": expected,
    })


def ratio_check(native_value: Any, hosted_value: Any,
                minimum: float, maximum: float) -> tuple[bool, float | None]:
    if not isinstance(native_value, (int, float)) or isinstance(native_value, bool):
        return False, None
    if not isinstance(hosted_value, (int, float)) or isinstance(hosted_value, bool):
        return False, None
    if native_value <= 0 or hosted_value < 0:
        return False, None
    ratio = float(hosted_value) / float(native_value)
    return minimum <= ratio <= maximum, ratio


def compare(native: dict[str, Any], hosted: dict[str, Any],
            thresholds: dict[str, Any]) -> dict[str, Any]:
    correctness: list[dict[str, Any]] = []
    runtime: list[dict[str, Any]] = []

    expected_scenario_id = thresholds.get("scenario_id")
    expected_parity_id = thresholds.get("parity_scenario_id")
    add_check(correctness, "threshold_schema_version",
              thresholds.get("schema_version") == 1,
              thresholds.get("schema_version"), 1)

    for label, report, expected_kind in (
        ("native", native, "native-linux"),
        ("hosted", hosted, "tcpcc"),
    ):
        add_check(correctness, f"{label}_schema_version",
                  report.get("schema_version") == 1,
                  report.get("schema_version"), 1)
        add_check(correctness, f"{label}_scenario_id",
                  report.get("scenario_id") == expected_scenario_id,
                  report.get("scenario_id"), expected_scenario_id)
        scenario = report.get("scenario")
        parity_id = scenario.get("parity_scenario_id") if isinstance(scenario, dict) else None
        add_check(correctness, f"{label}_parity_scenario_id",
                  parity_id == expected_parity_id, parity_id, expected_parity_id)
        runtime_info = report.get("runtime")
        runtime_kind = runtime_info.get("kind") if isinstance(runtime_info, dict) else None
        add_check(correctness, f"{label}_runtime_kind",
                  runtime_kind == expected_kind, runtime_kind, expected_kind)
        acceptance = report.get("acceptance")
        acceptance_passed = acceptance.get("passed") if isinstance(acceptance, dict) else None
        add_check(correctness, f"{label}_collector_acceptance",
                  acceptance_passed is True, acceptance_passed, True)

    add_check(correctness, "scenario_contract_matches",
              native.get("scenario") == hosted.get("scenario"),
              native.get("scenario"), hosted.get("scenario"))
    add_check(correctness, "upstream_pin_matches",
              native.get("upstream") == hosted.get("upstream"),
              native.get("upstream"), hosted.get("upstream"))

    scenario = native.get("scenario") if isinstance(native.get("scenario"), dict) else {}
    transfer = scenario.get("transfer") if isinstance(scenario.get("transfer"), dict) else {}
    expected_ccs = transfer.get("congestion_controls")
    if not isinstance(expected_ccs, list):
        expected_ccs = []
    expected_guest_to_host = transfer.get("guest_to_host_bytes_per_cc")
    expected_host_to_guest = transfer.get("host_to_guest_bytes_per_cc")

    native_ccs = native.get("congestion_controls")
    hosted_ccs = hosted.get("congestion_controls")
    if not isinstance(native_ccs, dict):
        native_ccs = {}
    if not isinstance(hosted_ccs, dict):
        hosted_ccs = {}
    add_check(correctness, "native_congestion_controls",
              sorted(native_ccs) == sorted(expected_ccs),
              sorted(native_ccs), sorted(expected_ccs))
    add_check(correctness, "hosted_congestion_controls",
              sorted(hosted_ccs) == sorted(expected_ccs),
              sorted(hosted_ccs), sorted(expected_ccs))

    for label, report in (("native", native), ("hosted", hosted)):
        path = report.get("path")
        qdisc = path.get("qdisc") if isinstance(path, dict) else None
        dropped = qdisc.get("dropped") if isinstance(qdisc, dict) else None
        add_check(correctness, f"{label}_qdisc_zero_drops", dropped == 0, dropped, 0)

    for cc_name in expected_ccs:
        native_fields = native_ccs.get(cc_name)
        hosted_fields = hosted_ccs.get(cc_name)
        if not isinstance(native_fields, dict):
            native_fields = {}
        if not isinstance(hosted_fields, dict):
            hosted_fields = {}
        for label, fields in (("native", native_fields), ("hosted", hosted_fields)):
            add_check(correctness, f"{label}_{cc_name}_guest_to_host_bytes",
                      fields.get("guest_to_host") == expected_guest_to_host,
                      fields.get("guest_to_host"), expected_guest_to_host)
            add_check(correctness, f"{label}_{cc_name}_host_to_guest_bytes",
                      fields.get("host_to_guest") == expected_host_to_guest,
                      fields.get("host_to_guest"), expected_host_to_guest)
            add_check(correctness, f"{label}_{cc_name}_established",
                      fields.get("state") == 1, fields.get("state"), 1)

        metric_config = thresholds.get("runtime_metrics")
        if not isinstance(metric_config, dict):
            metric_config = {}
        for metric, config in metric_config.items():
            if not isinstance(config, dict):
                continue
            minimum = float(config.get("min_ratio", 0.0))
            maximum = float(config.get("max_ratio", float("inf")))
            gate = bool(config.get("gate", False))
            passed, ratio = ratio_check(
                native_fields.get(metric), hosted_fields.get(metric), minimum, maximum
            )
            add_check(
                runtime,
                f"{cc_name}_{metric}_ratio",
                passed,
                {
                    "native": native_fields.get(metric),
                    "hosted": hosted_fields.get(metric),
                    "hosted_over_native": ratio,
                },
                {"min_ratio": minimum, "max_ratio": maximum},
                gate=gate,
            )

    observation_names = thresholds.get("observation_metrics")
    if not isinstance(observation_names, list):
        observation_names = []
    observations: dict[str, Any] = {}
    for cc_name in expected_ccs:
        native_fields = native_ccs.get(cc_name, {})
        hosted_fields = hosted_ccs.get(cc_name, {})
        observations[cc_name] = {
            metric: {
                "native": native_fields.get(metric),
                "hosted": hosted_fields.get(metric),
            }
            for metric in observation_names
        }

    correctness_passed = all(check["passed"] for check in correctness if check["gate"])
    runtime_gates = [check for check in runtime if check["gate"]]
    runtime_passed = all(check["passed"] for check in runtime_gates)
    status = "pass" if correctness_passed and runtime_passed else "fail"

    return {
        "schema_version": 1,
        "scenario_id": expected_scenario_id,
        "parity_scenario_id": expected_parity_id,
        "upstream": native.get("upstream"),
        "correctness": {
            "passed": correctness_passed,
            "checks": correctness,
        },
        "runtime_scheduling": {
            "passed": runtime_passed,
            "gated_checks": len(runtime_gates),
            "checks": runtime,
        },
        "observations": {
            "loss_counters": observations,
        },
        "status": status,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--hosted", required=True, type=Path)
    parser.add_argument("--thresholds", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    result = compare(
        read_json(args.native),
        read_json(args.hosted),
        read_json(args.thresholds),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "M7 lossless parity " + result["status"] + ": "
        f"correctness={result['correctness']['passed']} "
        f"runtime_scheduling={result['runtime_scheduling']['passed']}"
    )
    if result["status"] != "pass":
        failed = [
            check["name"]
            for section in (result["correctness"], result["runtime_scheduling"])
            for check in section["checks"]
            if check["gate"] and not check["passed"]
        ]
        print("failed gates: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

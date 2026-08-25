#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Collect a stable M7 hosted parity baseline from the proven M6.4 evidence."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any

TCP_FIELDS = (
    "guest_to_host",
    "host_to_guest",
    "state",
    "ca_state",
    "rto_us",
    "rtt_us",
    "rttvar_us",
    "snd_cwnd",
    "snd_ssthresh",
    "unacked",
    "lost",
    "retrans",
    "total_retrans",
    "pacing_rate",
    "max_pacing_rate",
    "delivery_rate",
)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return value


def read_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip("'\"")
    return result


def parse_tcp_log(path: Path, expected_ccs: list[str]) -> dict[str, dict[str, int]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    result: dict[str, dict[str, int]] = {}
    for cc_name in expected_ccs:
        prefix = f"{cc_name}:"
        matches = [line for line in lines if line.startswith(prefix)]
        if len(matches) != 1:
            raise SystemExit(
                f"{path}: expected exactly one {cc_name} telemetry line, got {len(matches)}"
            )
        fields = {
            key: int(value)
            for key, value in re.findall(r"([a-z_]+)=([0-9]+)", matches[0])
        }
        missing = [key for key in TCP_FIELDS if key not in fields]
        if missing:
            raise SystemExit(
                f"{path}: {cc_name} telemetry missing fields: {', '.join(missing)}"
            )
        result[cc_name] = {key: fields[key] for key in TCP_FIELDS}
    return result


def parse_ping(path: Path) -> dict[str, float]:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = "
        r"([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms",
        text,
    )
    if match is None:
        raise SystemExit(f"{path}: cannot parse delayed-path ping RTT")
    minimum, average, maximum, variation = map(float, match.groups())
    return {
        "min_ms": minimum,
        "avg_ms": average,
        "max_ms": maximum,
        "mdev_or_stddev_ms": variation,
    }


def parse_qdisc(path: Path) -> dict[str, int]:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        r"Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt\s+"
        r"\(dropped\s+(\d+),\s+overlimits\s+(\d+)\s+requeues\s+(\d+)\)",
        text,
    )
    if match is None:
        raise SystemExit(f"{path}: cannot parse netem qdisc counters")
    bytes_sent, packets_sent, dropped, overlimits, requeues = map(int, match.groups())
    return {
        "bytes_sent": bytes_sent,
        "packets_sent": packets_sent,
        "dropped": dropped,
        "overlimits": overlimits,
        "requeues": requeues,
    }


def add_check(checks: list[dict[str, Any]], name: str, passed: bool,
              observed: Any, expected: Any) -> None:
    checks.append({
        "name": name,
        "passed": bool(passed),
        "observed": observed,
        "expected": expected,
    })


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario-file", required=True, type=Path)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--upstream-env", required=True, type=Path)
    parser.add_argument("--tcp-log", required=True, type=Path)
    parser.add_argument("--ping-log", required=True, type=Path)
    parser.add_argument("--qdisc-log", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    contract = read_json(args.scenario_file)
    if contract.get("schema_version") != 1:
        raise SystemExit("unsupported M7 scenario schema_version")
    scenarios = contract.get("scenarios")
    if not isinstance(scenarios, dict) or args.scenario not in scenarios:
        raise SystemExit(f"unknown M7 scenario: {args.scenario}")
    scenario = scenarios[args.scenario]
    if not isinstance(scenario, dict):
        raise SystemExit(f"scenario {args.scenario} is not an object")

    network = scenario["network"]
    transfer = scenario["transfer"]
    acceptance = scenario["acceptance"]
    cc_names = transfer["congestion_controls"]
    if not isinstance(cc_names, list) or not cc_names:
        raise SystemExit("scenario has no congestion controls")

    upstream = read_env(args.upstream_env)
    required_upstream = ("UPSTREAM_TAG", "UPSTREAM_TAG_OBJECT", "UPSTREAM_COMMIT")
    missing_upstream = [key for key in required_upstream if not upstream.get(key)]
    if missing_upstream:
        raise SystemExit(
            f"{args.upstream_env}: missing upstream provenance: {', '.join(missing_upstream)}"
        )

    tcp = parse_tcp_log(args.tcp_log, cc_names)
    ping = parse_ping(args.ping_log)
    qdisc = parse_qdisc(args.qdisc_log)

    checks: list[dict[str, Any]] = []
    expected_guest_to_host = int(transfer["guest_to_host_bytes_per_cc"])
    expected_host_to_guest = int(transfer["host_to_guest_bytes_per_cc"])
    delay_ms = float(network["delay_ms"])
    min_rtt_fraction = float(acceptance["min_rtt_fraction_of_delay"])
    min_rtt_ms = delay_ms * min_rtt_fraction
    min_tcp_rtt_us = int(delay_ms * 1000.0 * min_rtt_fraction)

    add_check(
        checks,
        "configured_loss_is_zero",
        float(network["loss_percent"]) == 0.0,
        network["loss_percent"],
        0,
    )
    add_check(
        checks,
        "qdisc_carried_packets",
        qdisc["packets_sent"] > 0,
        qdisc["packets_sent"],
        "> 0",
    )
    if acceptance["require_qdisc_dropped_zero"]:
        add_check(
            checks,
            "qdisc_zero_drops",
            qdisc["dropped"] == 0,
            qdisc["dropped"],
            0,
        )
    add_check(
        checks,
        "ping_rtt_reflects_delay",
        ping["avg_ms"] >= min_rtt_ms,
        ping["avg_ms"],
        f">= {min_rtt_ms:.3f} ms",
    )

    for cc_name in cc_names:
        fields = tcp[cc_name]
        prefix = f"{cc_name}_"
        add_check(
            checks,
            prefix + "guest_to_host_bytes",
            fields["guest_to_host"] == expected_guest_to_host,
            fields["guest_to_host"],
            expected_guest_to_host,
        )
        add_check(
            checks,
            prefix + "host_to_guest_bytes",
            fields["host_to_guest"] == expected_host_to_guest,
            fields["host_to_guest"],
            expected_host_to_guest,
        )
        if acceptance["require_established"]:
            add_check(
                checks,
                prefix + "established",
                fields["state"] == 1,
                fields["state"],
                1,
            )
        if acceptance["require_nonzero_rto"]:
            add_check(
                checks,
                prefix + "nonzero_rto",
                fields["rto_us"] > 0,
                fields["rto_us"],
                "> 0",
            )
        if acceptance["require_nonzero_rtt"]:
            add_check(
                checks,
                prefix + "nonzero_rtt",
                fields["rtt_us"] > 0,
                fields["rtt_us"],
                "> 0",
            )
        if acceptance["require_nonzero_cwnd"]:
            add_check(
                checks,
                prefix + "nonzero_cwnd",
                fields["snd_cwnd"] > 0,
                fields["snd_cwnd"],
                "> 0",
            )
        add_check(
            checks,
            prefix + "tcp_rtt_reflects_delay",
            fields["rtt_us"] >= min_tcp_rtt_us,
            fields["rtt_us"],
            f">= {min_tcp_rtt_us} us",
        )

    if acceptance["require_bbr_pacing"]:
        if "bbr" not in tcp:
            raise SystemExit("scenario requires BBR pacing but does not include bbr")
        add_check(
            checks,
            "bbr_nonzero_pacing_rate",
            tcp["bbr"]["pacing_rate"] > 0,
            tcp["bbr"]["pacing_rate"],
            "> 0",
        )

    passed = all(check["passed"] for check in checks)
    report = {
        "schema_version": 1,
        "scenario_id": args.scenario,
        "scenario": scenario,
        "runtime": {
            "kind": "tcpcc",
            "arch": "tcpcc",
            "source_sha": os.environ.get("GITHUB_SHA", "unknown"),
        },
        "upstream": {
            "tag": upstream["UPSTREAM_TAG"],
            "tag_object": upstream["UPSTREAM_TAG_OBJECT"],
            "commit": upstream["UPSTREAM_COMMIT"],
        },
        "path": {
            "ping": ping,
            "qdisc": qdisc,
        },
        "congestion_controls": tcp,
        "acceptance": {
            "passed": passed,
            "checks": checks,
        },
        "native_reference": scenario["native_parity"],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if not passed:
        failed = ", ".join(check["name"] for check in checks if not check["passed"])
        raise SystemExit(f"M7 hosted baseline acceptance failed: {failed}")

    print(
        f"M7 hosted baseline passed: scenario={args.scenario} "
        f"ping_avg_ms={ping['avg_ms']:.3f} qdisc_dropped={qdisc['dropped']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Collect the M7.2 pinned native Linux lossless reference report."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
from pathlib import Path
from types import ModuleType
from typing import Any


def load_hosted_helpers() -> ModuleType:
    helper_path = Path(__file__).with_name("collect-m7-hosted-report.py")
    spec = importlib.util.spec_from_file_location("m7_hosted_report", helper_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load M7 helper module: {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extract_marker(text: str, name: str) -> str:
    pattern = re.compile(rf"^{re.escape(name)}=(.+)$", re.MULTILINE)
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise SystemExit(f"native log: expected exactly one {name}, got {len(matches)}")
    return matches[0].strip()


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
    parser.add_argument("--virtme-env", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    common = load_hosted_helpers()
    contract = common.read_json(args.scenario_file)
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

    upstream = common.read_env(args.upstream_env)
    required_upstream = (
        "LINUX_REMOTE",
        "LINUX_SERIES",
        "LINUX_TAG",
        "LINUX_VERSION",
        "LINUX_COMMIT",
    )
    missing_upstream = [key for key in required_upstream if not upstream.get(key)]
    if missing_upstream:
        raise SystemExit(
            f"{args.upstream_env}: missing upstream provenance: "
            f"{', '.join(missing_upstream)}"
        )

    virtme = common.read_env(args.virtme_env)
    required_virtme = ("VIRTME_NG_REMOTE", "VIRTME_NG_COMMIT")
    missing_virtme = [key for key in required_virtme if not virtme.get(key)]
    if missing_virtme:
        raise SystemExit(
            f"{args.virtme_env}: missing virtme-ng provenance: "
            f"{', '.join(missing_virtme)}"
        )

    text = args.log.read_text(encoding="utf-8")
    kernel_release = extract_marker(text, "M7_NATIVE_KERNEL_RELEASE")
    clocksource = extract_marker(text, "M7_NATIVE_CLOCKSOURCE")
    available_cc = extract_marker(text, "M7_NATIVE_AVAILABLE_CC").split()

    tcp = common.parse_tcp_log(args.log, cc_names)
    ping = common.parse_ping(args.log)
    qdisc = common.parse_qdisc(args.log)

    expected_release = (
        f"{upstream['LINUX_VERSION']}-m7-{upstream['LINUX_COMMIT'][:12]}"
    )
    checks: list[dict[str, Any]] = []
    add_check(
        checks,
        "native_kernel_release_matches_pin",
        kernel_release == expected_release,
        kernel_release,
        expected_release,
    )
    add_check(
        checks,
        "native_clocksource_is_kvm_clock",
        clocksource == "kvm-clock",
        clocksource,
        "kvm-clock",
    )
    for cc_name in cc_names:
        add_check(
            checks,
            f"native_{cc_name}_available",
            cc_name in available_cc,
            available_cc,
            f"contains {cc_name}",
        )

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
    native_reference = dict(scenario["native_parity"])
    native_reference.update({
        "status": "measured_m7_2",
        "kernel_release": kernel_release,
        "clocksource": clocksource,
        "virtme_ng_commit": virtme["VIRTME_NG_COMMIT"],
    })
    report = {
        "schema_version": 1,
        "scenario_id": args.scenario,
        "scenario": scenario,
        "runtime": {
            "kind": "native-linux",
            "arch": "x86_64",
            "source_sha": os.environ.get("GITHUB_SHA", "unknown"),
            "kernel_release": kernel_release,
            "clocksource": clocksource,
        },
        "upstream": {
            "remote": upstream["LINUX_REMOTE"],
            "series": upstream["LINUX_SERIES"],
            "tag": upstream["LINUX_TAG"],
            "version": upstream["LINUX_VERSION"],
            "commit": upstream["LINUX_COMMIT"],
        },
        "harness": {
            "remote": virtme["VIRTME_NG_REMOTE"],
            "commit": virtme["VIRTME_NG_COMMIT"],
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
        "native_reference": native_reference,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if not passed:
        failed = ", ".join(check["name"] for check in checks if not check["passed"])
        raise SystemExit(f"M7 native baseline acceptance failed: {failed}")

    print(
        f"M7 native baseline passed: release={kernel_release} "
        f"ping_avg_ms={ping['avg_ms']:.3f} qdisc_dropped={qdisc['dropped']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compare native CUBIC/BBR and tcpcc BBR with reverse iperf3."""

from __future__ import annotations

import argparse
import errno
import json
import math
import os
import re
import secrets
import shutil
import signal
import statistics
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCENARIO = ROOT / "benchmarks/m8/iperf-high-bdp-loss-v1.json"

SERVER_ADDRESS = "10.203.0.2"
SERVER_PREFIX = 24
SERVER_NETWORK = "10.203.0.0/24"
WAN_SERVER_ADDRESS = "10.203.0.1"
CLIENT_ADDRESS = "10.203.1.2"
CLIENT_PREFIX = 24
CLIENT_NETWORK = "10.203.1.0/24"
WAN_CLIENT_ADDRESS = "10.203.1.1"
NATIVE_PORT = 46001
TCPCC_PUBLIC_PORT = 46002
TCPCC_BACKEND_PORT = 46003
TCPCC_TUN_HOST_ADDRESS = "198.18.0.1"
TCPCC_TUN_GUEST_ADDRESS = "198.18.0.2"

CASES = ("native_cubic", "native_bbr", "tcpcc_bbr")
PING_RTT = re.compile(
    r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = "
    r"([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms"
)


@dataclass(frozen=True)
class Scenario:
    raw: dict[str, Any]
    scenario_id: str
    rate_mbps: int
    one_way_delay_ms: int
    random_loss_percent: float
    netem_limit_packets: int
    mtu: int
    duration_seconds: int
    omit_seconds: int
    repetitions: int
    settle_seconds: float
    minimum_goodput_mbps: float
    tcpcc_to_native_bbr_min_ratio: float
    tcpcc_to_native_bbr_max_ratio: float

    @property
    def rtt_ms(self) -> int:
        return 2 * self.one_way_delay_ms

    @property
    def bdp_bytes(self) -> int:
        return round(
            self.rate_mbps
            * 1_000_000
            / 8
            * self.rtt_ms
            / 1000
        )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _number(
    value: Any,
    label: str,
    minimum: float,
    maximum: float,
    *,
    integer: bool = False,
) -> float | int:
    expected = int if integer else (int, float)
    if isinstance(value, bool) or not isinstance(value, expected):
        kind = "integer" if integer else "number"
        raise ValueError(f"{label} must be a {kind}")
    if not math.isfinite(float(value)) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be from {minimum:g} through {maximum:g}")
    return int(value) if integer else float(value)


def parse_scenario(value: Any) -> Scenario:
    document = _object(value, "scenario")
    if document.get("schema_version") != 1:
        raise ValueError("scenario schema_version must be 1")
    scenario_id = document.get("scenario_id")
    if not isinstance(scenario_id, str) or not scenario_id:
        raise ValueError("scenario_id must be a nonempty string")

    network = _object(document.get("network"), "network")
    iperf = _object(document.get("iperf"), "iperf")
    acceptance = _object(document.get("acceptance"), "acceptance")
    if iperf.get("parallel_streams") != 1:
        raise ValueError("iperf.parallel_streams must be exactly 1")
    if acceptance.get("bbr_over_cubic_is_observational") is not True:
        raise ValueError(
            "acceptance.bbr_over_cubic_is_observational must be true"
        )

    scenario = Scenario(
        raw=document,
        scenario_id=scenario_id,
        rate_mbps=int(
            _number(network.get("rate_mbps"), "network.rate_mbps", 1, 10000,
                    integer=True)
        ),
        one_way_delay_ms=int(
            _number(
                network.get("one_way_delay_ms"),
                "network.one_way_delay_ms",
                1,
                1000,
                integer=True,
            )
        ),
        random_loss_percent=float(
            _number(
                network.get("random_loss_percent"),
                "network.random_loss_percent",
                0.001,
                5,
            )
        ),
        netem_limit_packets=int(
            _number(
                network.get("netem_limit_packets"),
                "network.netem_limit_packets",
                100,
                1_000_000,
                integer=True,
            )
        ),
        mtu=int(
            _number(network.get("mtu"), "network.mtu", 576, 9000,
                    integer=True)
        ),
        duration_seconds=int(
            _number(
                iperf.get("duration_seconds"),
                "iperf.duration_seconds",
                3,
                120,
                integer=True,
            )
        ),
        omit_seconds=int(
            _number(
                iperf.get("omit_seconds"),
                "iperf.omit_seconds",
                0,
                30,
                integer=True,
            )
        ),
        repetitions=int(
            _number(
                iperf.get("repetitions"),
                "iperf.repetitions",
                3,
                9,
                integer=True,
            )
        ),
        settle_seconds=float(
            _number(
                iperf.get("settle_seconds"),
                "iperf.settle_seconds",
                0,
                10,
            )
        ),
        minimum_goodput_mbps=float(
            _number(
                acceptance.get("minimum_goodput_mbps"),
                "acceptance.minimum_goodput_mbps",
                0.001,
                10000,
            )
        ),
        tcpcc_to_native_bbr_min_ratio=float(
            _number(
                acceptance.get("tcpcc_to_native_bbr_min_ratio"),
                "acceptance.tcpcc_to_native_bbr_min_ratio",
                0.01,
                10,
            )
        ),
        tcpcc_to_native_bbr_max_ratio=float(
            _number(
                acceptance.get("tcpcc_to_native_bbr_max_ratio"),
                "acceptance.tcpcc_to_native_bbr_max_ratio",
                0.01,
                10,
            )
        ),
    )
    if (
        scenario.tcpcc_to_native_bbr_min_ratio
        >= scenario.tcpcc_to_native_bbr_max_ratio
    ):
        raise ValueError("tcpcc/native BBR ratio bounds are reversed")
    if scenario.omit_seconds >= scenario.duration_seconds:
        raise ValueError("iperf.omit_seconds must be less than duration_seconds")
    if scenario.netem_limit_packets * scenario.mtu < 2 * scenario.bdp_bytes:
        raise ValueError("netem queue must hold at least two path BDPs")
    return scenario


def load_scenario(path: Path) -> Scenario:
    return parse_scenario(json.loads(path.read_text(encoding="utf-8")))


def parse_iperf_document(
    value: Any,
    *,
    expected_sender_cc: str,
) -> dict[str, Any]:
    document = _object(value, "iperf result")
    if document.get("error"):
        raise ValueError(f"iperf reported an error: {document['error']}")
    start = _object(document.get("start"), "iperf start")
    test_start = _object(start.get("test_start"), "iperf test_start")
    if test_start.get("protocol") != "TCP":
        raise ValueError("iperf result is not TCP")
    if test_start.get("reverse") != 1:
        raise ValueError("iperf result is not reverse/server-sender mode")
    if test_start.get("num_streams") != 1:
        raise ValueError("iperf result is not single-stream")

    end = _object(document.get("end"), "iperf end")
    received = _object(end.get("sum_received"), "iperf sum_received")
    sent = _object(end.get("sum_sent"), "iperf sum_sent")
    sender_cc = end.get("sender_tcp_congestion")
    if sender_cc != expected_sender_cc:
        raise ValueError(
            f"iperf sender congestion control is {sender_cc!r}, "
            f"expected {expected_sender_cc!r}"
        )
    bits_per_second = received.get("bits_per_second")
    received_bytes = received.get("bytes")
    retransmits = sent.get("retransmits")
    seconds = received.get("seconds")
    for field, observed in (
        ("bits_per_second", bits_per_second),
        ("received bytes", received_bytes),
        ("seconds", seconds),
    ):
        if (
            isinstance(observed, bool)
            or not isinstance(observed, (int, float))
            or not math.isfinite(float(observed))
            or observed <= 0
        ):
            raise ValueError(f"iperf {field} is invalid: {observed!r}")
    if (
        isinstance(retransmits, bool)
        or not isinstance(retransmits, int)
        or retransmits < 0
    ):
        raise ValueError(f"iperf retransmits is invalid: {retransmits!r}")
    return {
        "bits_per_second": float(bits_per_second),
        "goodput_mbps": float(bits_per_second) / 1_000_000,
        "received_bytes": int(received_bytes),
        "seconds": float(seconds),
        "retransmits": retransmits,
        "sender_tcp_congestion": sender_cc,
        "receiver_tcp_congestion": end.get("receiver_tcp_congestion"),
    }


def summarize_measurements(
    measurements: dict[str, list[dict[str, Any]]],
    scenario: Scenario,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], bool]:
    summaries: dict[str, dict[str, Any]] = {}
    checks: list[dict[str, Any]] = []

    def add_check(
        name: str,
        passed: bool,
        observed: Any,
        expected: Any,
        *,
        gate: bool = True,
    ) -> None:
        checks.append(
            {
                "name": name,
                "gate": gate,
                "passed": bool(passed),
                "observed": observed,
                "expected": expected,
            }
        )

    for case in CASES:
        runs = measurements.get(case, [])
        add_check(
            f"{case}_repetitions",
            len(runs) == scenario.repetitions,
            len(runs),
            scenario.repetitions,
        )
        if not runs:
            continue
        goodputs = [float(run["goodput_mbps"]) for run in runs]
        retransmits = [int(run["retransmits"]) for run in runs]
        summaries[case] = {
            "median_goodput_mbps": statistics.median(goodputs),
            "minimum_goodput_mbps": min(goodputs),
            "maximum_goodput_mbps": max(goodputs),
            "median_retransmits": statistics.median(retransmits),
            "total_retransmits": sum(retransmits),
        }
        add_check(
            f"{case}_minimum_goodput",
            min(goodputs) >= scenario.minimum_goodput_mbps,
            min(goodputs),
            f">= {scenario.minimum_goodput_mbps} Mbps",
        )

    if all(case in summaries for case in CASES):
        cubic = summaries["native_cubic"]["median_goodput_mbps"]
        native_bbr = summaries["native_bbr"]["median_goodput_mbps"]
        tcpcc_bbr = summaries["tcpcc_bbr"]["median_goodput_mbps"]
        native_bbr_over_cubic = native_bbr / cubic
        tcpcc_bbr_over_cubic = tcpcc_bbr / cubic
        tcpcc_to_native_bbr = tcpcc_bbr / native_bbr
        summaries["comparisons"] = {
            "native_bbr_over_native_cubic": native_bbr_over_cubic,
            "tcpcc_bbr_over_native_cubic": tcpcc_bbr_over_cubic,
            "tcpcc_bbr_over_native_bbr": tcpcc_to_native_bbr,
        }
        add_check(
            "tcpcc_to_native_bbr_ratio",
            scenario.tcpcc_to_native_bbr_min_ratio
            <= tcpcc_to_native_bbr
            <= scenario.tcpcc_to_native_bbr_max_ratio,
            tcpcc_to_native_bbr,
            {
                "minimum": scenario.tcpcc_to_native_bbr_min_ratio,
                "maximum": scenario.tcpcc_to_native_bbr_max_ratio,
            },
        )
        add_check(
            "native_bbr_over_cubic_observation",
            native_bbr_over_cubic >= 1,
            native_bbr_over_cubic,
            ">= 1 (observation only)",
            gate=False,
        )
        add_check(
            "tcpcc_bbr_over_cubic_observation",
            tcpcc_bbr_over_cubic >= 1,
            tcpcc_bbr_over_cubic,
            ">= 1 (observation only)",
            gate=False,
        )

    passed = all(check["passed"] for check in checks if check["gate"])
    return summaries, checks, passed


def run(
    command: list[str],
    *,
    check: bool = True,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed with {completed.returncode}: {' '.join(command)}\n"
            f"{completed.stdout}"
        )
    return completed


def ns_command(namespace: str, *command: str) -> list[str]:
    return ["ip", "netns", "exec", namespace, *command]


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def start_logged_process(
    command: list[str],
    path: Path,
) -> subprocess.Popen[bytes]:
    stream = path.open("wb")
    try:
        return subprocess.Popen(
            command,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        stream.close()


def stop_process(process: subprocess.Popen[object] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def wait_listener(
    namespace: str,
    port: int,
    process: subprocess.Popen[object],
    timeout: float = 10.0,
) -> None:
    deadline = time.monotonic() + timeout
    needle = f":{port}"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"listener process exited with {process.returncode} on port {port}"
            )
        sockets = run(
            ns_command(namespace, "ss", "-H", "-lnt"),
            check=False,
        )
        if any(needle in line.split()[3] for line in sockets.stdout.splitlines()
               if len(line.split()) >= 4):
            return
        time.sleep(0.05)
    raise TimeoutError(f"listener on port {port} did not become ready")


def read_events(path: Path) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    if not path.exists():
        return documents
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("tcpcc event is not a JSON object")
        documents.append(value)
    return documents


def wait_tcpcc_ready(
    event_path: Path,
    process: subprocess.Popen[object],
    timeout: float = 20.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for event in read_events(event_path):
            if event.get("event") == "ready":
                return event
        if process.poll() is not None:
            raise RuntimeError(
                f"tcpcc exited with {process.returncode} before readiness"
            )
        time.sleep(0.05)
    raise TimeoutError("tcpcc did not become ready")


def setup_topology(
    scenario: Scenario,
    names: dict[str, str],
) -> str:
    server = names["server_ns"]
    wan = names["wan_ns"]
    client = names["client_ns"]
    namespaces = (server, wan, client)
    for namespace in namespaces:
        run(["ip", "netns", "add", namespace])

    run(
        [
            "ip", "link", "add", names["server_dev"], "type", "veth",
            "peer", "name", names["wan_server_dev"],
        ]
    )
    run(
        [
            "ip", "link", "add", names["wan_client_dev"], "type", "veth",
            "peer", "name", names["client_dev"],
        ]
    )
    for device, namespace in (
        (names["server_dev"], server),
        (names["wan_server_dev"], wan),
        (names["wan_client_dev"], wan),
        (names["client_dev"], client),
    ):
        run(["ip", "link", "set", device, "netns", namespace])

    for namespace in namespaces:
        run(ns_command(namespace, "ip", "link", "set", "lo", "up"))
    endpoints = (
        (server, names["server_dev"], SERVER_ADDRESS, SERVER_PREFIX),
        (wan, names["wan_server_dev"], WAN_SERVER_ADDRESS, SERVER_PREFIX),
        (wan, names["wan_client_dev"], WAN_CLIENT_ADDRESS, CLIENT_PREFIX),
        (client, names["client_dev"], CLIENT_ADDRESS, CLIENT_PREFIX),
    )
    for namespace, device, address, prefix in endpoints:
        run(
            ns_command(
                namespace,
                "ip",
                "address",
                "add",
                f"{address}/{prefix}",
                "dev",
                device,
            )
        )
        run(
            ns_command(
                namespace,
                "ip",
                "link",
                "set",
                "dev",
                device,
                "mtu",
                str(scenario.mtu),
                "up",
            )
        )
        run(
            ns_command(
                namespace,
                "ethtool",
                "-K",
                device,
                "gro",
                "off",
                "gso",
                "off",
                "tso",
                "off",
            )
        )

    run(
        ns_command(
            server,
            "ip",
            "route",
            "add",
            CLIENT_NETWORK,
            "via",
            WAN_SERVER_ADDRESS,
        )
    )
    run(
        ns_command(
            client,
            "ip",
            "route",
            "add",
            SERVER_NETWORK,
            "via",
            WAN_CLIENT_ADDRESS,
        )
    )

    for namespace, settings in (
        (
            server,
            (
                "net.ipv4.ip_forward=1",
                "net.ipv4.tcp_congestion_control=bbr",
                "net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.default.rp_filter=0",
                f"net.ipv4.conf.{names['server_dev']}.rp_filter=0",
            ),
        ),
        (
            wan,
            (
                "net.ipv4.ip_forward=1",
                "net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.default.rp_filter=0",
                f"net.ipv4.conf.{names['wan_server_dev']}.rp_filter=0",
                f"net.ipv4.conf.{names['wan_client_dev']}.rp_filter=0",
            ),
        ),
        (
            client,
            (
                "net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.default.rp_filter=0",
                f"net.ipv4.conf.{names['client_dev']}.rp_filter=0",
            ),
        ),
    ):
        for setting in settings:
            run(ns_command(namespace, "sysctl", "-q", "-w", setting))

    available = run(
        ns_command(
            server,
            "cat",
            "/proc/sys/net/ipv4/tcp_available_congestion_control",
        )
    ).stdout.strip()
    for cc_name in ("cubic", "bbr"):
        if cc_name not in available.split():
            raise RuntimeError(f"native congestion control unavailable: {cc_name}")

    run(
        ns_command(
            server,
            "tc",
            "qdisc",
            "replace",
            "dev",
            names["server_dev"],
            "root",
            "fq",
        )
    )
    run(
        ns_command(
            client,
            "tc",
            "qdisc",
            "replace",
            "dev",
            names["client_dev"],
            "root",
            "fq",
        )
    )
    for device in (names["wan_server_dev"], names["wan_client_dev"]):
        run(
            ns_command(
                wan,
                "tc",
                "qdisc",
                "replace",
                "dev",
                device,
                "root",
                "netem",
                "limit",
                str(scenario.netem_limit_packets),
                "delay",
                f"{scenario.one_way_delay_ms}ms",
                "loss",
                "random",
                f"{scenario.random_loss_percent:g}%",
                "rate",
                f"{scenario.rate_mbps}mbit",
            )
        )

    lines = [
        f"available_cc={available}",
        f"configured_rtt_ms={scenario.rtt_ms}",
        f"configured_bdp_bytes={scenario.bdp_bytes}",
    ]
    for namespace in namespaces:
        lines.append(f"## {namespace} addresses")
        lines.append(run(ns_command(namespace, "ip", "-br", "address")).stdout)
        lines.append(f"## {namespace} routes")
        lines.append(run(ns_command(namespace, "ip", "route")).stdout)
    return "\n".join(lines)


def qdisc_report(names: dict[str, str]) -> str:
    records: list[str] = []
    for namespace, device in (
        (names["server_ns"], names["server_dev"]),
        (names["wan_ns"], names["wan_server_dev"]),
        (names["wan_ns"], names["wan_client_dev"]),
        (names["client_ns"], names["client_dev"]),
    ):
        records.append(f"## {namespace}/{device}")
        records.append(
            run(
                ns_command(
                    namespace,
                    "tc",
                    "-s",
                    "qdisc",
                    "show",
                    "dev",
                    device,
                )
            ).stdout
        )
    return "\n".join(records)


def parse_qdisc_document(
    value: Any,
    *,
    expected_kind: str,
    scenario: Scenario,
) -> dict[str, Any]:
    if not isinstance(value, list):
        raise ValueError("tc qdisc JSON must be an array")
    entry = next(
        (
            item
            for item in value
            if isinstance(item, dict)
            and item.get("root") is True
            and item.get("kind") == expected_kind
        ),
        None,
    )
    if entry is None:
        raise ValueError(f"root qdisc is not {expected_kind}")
    for field in ("bytes", "packets", "drops", "overlimits", "backlog"):
        observed = entry.get(field)
        if isinstance(observed, bool) or not isinstance(observed, int) or observed < 0:
            raise ValueError(f"{expected_kind} qdisc {field} is invalid: {observed!r}")

    if expected_kind == "netem":
        options = _object(entry.get("options"), "netem options")
        delay = _object(options.get("delay"), "netem delay").get("delay")
        loss = _object(options.get("loss-random"), "netem loss").get("loss")
        rate = _object(options.get("rate"), "netem rate").get("rate")
        expected_delay = scenario.one_way_delay_ms / 1000
        expected_loss = scenario.random_loss_percent / 100
        expected_rate = scenario.rate_mbps * 1_000_000 / 8
        for label, observed, expected in (
            ("delay", delay, expected_delay),
            ("loss", loss, expected_loss),
            ("rate", rate, expected_rate),
        ):
            if (
                isinstance(observed, bool)
                or not isinstance(observed, (int, float))
                or not math.isclose(float(observed), expected, rel_tol=1e-9)
            ):
                raise ValueError(
                    f"netem {label} is {observed!r}, expected {expected!r}"
                )
        if options.get("limit") != scenario.netem_limit_packets:
            raise ValueError("netem packet limit does not match the scenario")

    packets = int(entry["packets"])
    drops = int(entry["drops"])
    denominator = packets + drops
    return {
        "kind": expected_kind,
        "bytes": int(entry["bytes"]),
        "packets": packets,
        "drops": drops,
        "overlimits": int(entry["overlimits"]),
        "backlog_bytes": int(entry["backlog"]),
        "observed_drop_percent": (
            100 * drops / denominator if denominator else 0.0
        ),
    }


def collect_qdisc_observations(
    names: dict[str, str],
    scenario: Scenario,
) -> dict[str, dict[str, Any]]:
    observations: dict[str, dict[str, Any]] = {}
    for label, namespace, device, kind in (
        (
            "server_endpoint",
            names["server_ns"],
            names["server_dev"],
            "fq",
        ),
        (
            "client_endpoint",
            names["client_ns"],
            names["client_dev"],
            "fq",
        ),
        (
            "ack_direction",
            names["wan_ns"],
            names["wan_server_dev"],
            "netem",
        ),
        (
            "data_direction",
            names["wan_ns"],
            names["wan_client_dev"],
            "netem",
        ),
    ):
        raw = run(
            ns_command(
                namespace,
                "tc",
                "-s",
                "-j",
                "qdisc",
                "show",
                "dev",
                device,
            )
        ).stdout
        observations[label] = parse_qdisc_document(
            json.loads(raw),
            expected_kind=kind,
            scenario=scenario,
        )
    return observations


def ping_path(
    names: dict[str, str],
    scenario: Scenario,
) -> tuple[dict[str, float], str]:
    completed = run(
        ns_command(
            names["client_ns"],
            "ping",
            "-4",
            "-n",
            "-c",
            "10",
            "-i",
            "0.2",
            "-W",
            "2",
            SERVER_ADDRESS,
        ),
        timeout=30,
    )
    match = PING_RTT.search(completed.stdout)
    if match is None:
        raise RuntimeError("could not parse high-BDP ping RTT")
    minimum, average, maximum, deviation = map(float, match.groups())
    if not 0.7 * scenario.rtt_ms <= average <= 1.5 * scenario.rtt_ms:
        raise RuntimeError(
            f"observed RTT {average} ms does not reflect configured "
            f"{scenario.rtt_ms} ms"
        )
    return {
        "minimum_ms": minimum,
        "average_ms": average,
        "maximum_ms": maximum,
        "deviation_ms": deviation,
    }, completed.stdout


def run_iperf_measurement(
    names: dict[str, str],
    scenario: Scenario,
    output_dir: Path,
    *,
    case: str,
    round_number: int,
    order: int,
) -> dict[str, Any]:
    if case not in CASES:
        raise ValueError(f"unknown iperf case {case}")
    public_port = TCPCC_PUBLIC_PORT if case == "tcpcc_bbr" else NATIVE_PORT
    cc_name = "cubic" if case == "native_cubic" else "bbr"
    command = ns_command(
        names["client_ns"],
        "iperf3",
        "-4",
        "--client",
        SERVER_ADDRESS,
        "--port",
        str(public_port),
        "--reverse",
        "--parallel",
        "1",
        "--omit",
        str(scenario.omit_seconds),
        "--time",
        str(scenario.duration_seconds),
        "--congestion",
        cc_name,
        "--connect-timeout",
        "5000",
        "--get-server-output",
        "--json",
        "--extra-data",
        f"{case}-round-{round_number}",
    )
    timeout = scenario.duration_seconds + scenario.omit_seconds + 30
    completed = run(command, check=False, timeout=timeout)
    stem = f"iperf-{case}-round-{round_number}"
    write_text(output_dir / f"{stem}.json", completed.stdout)
    if completed.returncode != 0:
        raise RuntimeError(
            f"{case} round {round_number} failed with {completed.returncode}:\n"
            f"{completed.stdout}"
        )
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{case} emitted invalid iperf JSON") from error
    result = parse_iperf_document(document, expected_sender_cc=cc_name)
    result.update(
        {
            "case": case,
            "round": round_number,
            "order": order,
            "public_port": public_port,
            "raw_artifact": f"{stem}.json",
        }
    )
    return result


def validate_tcpcc_events(
    events: list[dict[str, Any]],
    scenario: Scenario,
) -> dict[str, Any]:
    ready = next((event for event in events if event.get("event") == "ready"), None)
    stopped = next(
        (event for event in events if event.get("event") == "stopped"),
        None,
    )
    if ready is None or ready.get("cc") != "bbr":
        raise RuntimeError("tcpcc readiness did not prove BBR")
    if stopped is None or stopped.get("clean") is not True:
        raise RuntimeError("tcpcc did not report a clean stop")
    if any(
        event.get("event") in {"connection-rejected", "drain-timeout"}
        for event in events
    ):
        raise RuntimeError("tcpcc rejected or timed out an iperf connection")
    opened = [event for event in events if event.get("event") == "connection-opened"]
    closed = [event for event in events if event.get("event") == "connection-closed"]
    if len(opened) < scenario.repetitions:
        raise RuntimeError(
            f"tcpcc opened only {len(opened)} public connections for "
            f"{scenario.repetitions} iperf runs"
        )
    if len(closed) != len(opened):
        raise RuntimeError(
            f"tcpcc terminal count {len(closed)} != opened count {len(opened)}"
        )
    if any(event.get("accepted_cc") != "bbr" for event in opened):
        raise RuntimeError("a tcpcc public connection did not inherit BBR")
    minimum_data_bytes = round(
        scenario.minimum_goodput_mbps
        * 1_000_000
        / 8
        * scenario.duration_seconds
        * 0.5
    )
    data_flows = [
        event
        for event in closed
        if int(event.get("backend_to_public_bytes", 0)) >= minimum_data_bytes
    ]
    if len(data_flows) < scenario.repetitions:
        raise RuntimeError(
            f"tcpcc reported only {len(data_flows)} completed data flows"
        )
    allowed_data_statuses = {0, -errno.ECONNRESET}
    invalid_data_statuses = [
        event.get("status")
        for event in data_flows
        if event.get("status") not in allowed_data_statuses
    ]
    if invalid_data_statuses:
        raise RuntimeError(
            "tcpcc data flows returned unexpected terminal statuses: "
            f"{invalid_data_statuses}"
        )
    control_flows = [event for event in closed if event not in data_flows]
    if len(control_flows) < scenario.repetitions:
        raise RuntimeError(
            f"tcpcc reported only {len(control_flows)} completed control flows"
        )
    if any(event.get("status") != 0 for event in control_flows):
        raise RuntimeError("an iperf control flow did not close cleanly")
    terminal_statuses: dict[str, int] = {}
    for event in closed:
        status = str(event.get("status"))
        terminal_statuses[status] = terminal_statuses.get(status, 0) + 1
    return {
        "ready": ready,
        "opened_connections": len(opened),
        "closed_connections": len(closed),
        "completed_data_flows": len(data_flows),
        "completed_control_flows": len(control_flows),
        "terminal_statuses": terminal_statuses,
        "data_terminal_policy": "clean EOF or iperf3 abortive-close ECONNRESET",
        "accepted_cc": "bbr",
        "clean_stop": True,
    }


def assert_tcpcc_resources_removed(
    names: dict[str, str],
    ready: dict[str, Any],
) -> None:
    tun_name = ready.get("tun")
    firewall_resource = ready.get("firewall_resource")
    if not isinstance(tun_name, str) or not tun_name:
        raise RuntimeError("tcpcc readiness omitted the TUN name")
    if not isinstance(firewall_resource, str) or not firewall_resource:
        raise RuntimeError("tcpcc readiness omitted the firewall resource")
    link = run(
        ns_command(
            names["server_ns"],
            "ip",
            "link",
            "show",
            "dev",
            tun_name,
        ),
        check=False,
    )
    if link.returncode == 0:
        raise RuntimeError(f"owned TUN {tun_name} survived benchmark shutdown")
    table = run(
        ns_command(
            names["server_ns"],
            "nft",
            "list",
            "table",
            "ip",
            firewall_resource,
        ),
        check=False,
    )
    if table.returncode == 0:
        raise RuntimeError(
            f"owned nftables table {firewall_resource} survived benchmark shutdown"
        )


def collect_environment(names: dict[str, str], kernel: Path) -> dict[str, Any]:
    iperf_version = run(["iperf3", "--version"]).stdout.splitlines()[0]
    tcpcc_commit = os.environ.get("GITHUB_SHA")
    if tcpcc_commit is None and shutil.which("git") is not None:
        observed = run(
            ["git", "rev-parse", "HEAD"],
            check=False,
            timeout=10,
        )
        if observed.returncode == 0:
            tcpcc_commit = observed.stdout.strip()
    return {
        "native_kernel_release": run(
            ns_command(names["server_ns"], "uname", "-r")
        ).stdout.strip(),
        "iperf_version": iperf_version,
        "hosted_kernel_path": str(kernel),
        "tcpcc_commit": tcpcc_commit or "unknown",
    }


def benchmark(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise PermissionError("--integration requires root")
    for command in ("ethtool", "ip", "iperf3", "nft", "ss", "sysctl", "tc"):
        if shutil.which(command) is None:
            raise FileNotFoundError(f"required command is unavailable: {command}")
    kernel = args.kernel.resolve(strict=True)
    if not os.access(kernel, os.X_OK):
        raise PermissionError(f"hosted kernel is not executable: {kernel}")
    scenario = load_scenario(args.scenario_file)
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    suffix = secrets.token_hex(3)
    names = {
        "server_ns": f"tcps{suffix}",
        "wan_ns": f"tcpw{suffix}",
        "client_ns": f"tcpc{suffix}",
        "server_dev": f"ts{suffix}",
        "wan_server_dev": f"tws{suffix}",
        "wan_client_dev": f"twc{suffix}",
        "client_dev": f"tc{suffix}",
        "tun_name": f"tb{suffix}",
    }
    namespaces: list[str] = []
    native_server: subprocess.Popen[bytes] | None = None
    backend_server: subprocess.Popen[bytes] | None = None
    tcpcc_process: subprocess.Popen[bytes] | None = None
    tcpcc_ready: dict[str, Any] | None = None
    event_path = output_dir / "tcpcc-events.jsonl"
    diagnostic_path = output_dir / "tcpcc.log"
    measurements: dict[str, list[dict[str, Any]]] = {
        case: [] for case in CASES
    }

    try:
        for key in ("server_ns", "wan_ns", "client_ns"):
            namespaces.append(names[key])
        topology = setup_topology(scenario, names)
        write_text(output_dir / "topology.txt", topology)
        write_text(output_dir / "qdisc-before.txt", qdisc_report(names))
        ping, ping_log = ping_path(names, scenario)
        write_text(output_dir / "ping.txt", ping_log)
        environment = collect_environment(names, kernel)

        native_server = start_logged_process(
            ns_command(
                names["server_ns"],
                "iperf3",
                "--server",
                "--bind",
                SERVER_ADDRESS,
                "--port",
                str(NATIVE_PORT),
                "--forceflush",
            ),
            output_dir / "iperf-native-server.log",
        )
        wait_listener(names["server_ns"], NATIVE_PORT, native_server)

        backend_server = start_logged_process(
            ns_command(
                names["server_ns"],
                "iperf3",
                "--server",
                "--bind",
                "127.0.0.1",
                "--port",
                str(TCPCC_BACKEND_PORT),
                "--forceflush",
            ),
            output_dir / "iperf-tcpcc-backend.log",
        )
        wait_listener(names["server_ns"], TCPCC_BACKEND_PORT, backend_server)

        event_stream = event_path.open("wb")
        diagnostic_stream = diagnostic_path.open("wb")
        try:
            tcpcc_process = subprocess.Popen(
                ns_command(
                    names["server_ns"],
                    str(ROOT / "tcpcc"),
                    "--listen",
                    f"{SERVER_ADDRESS}:{TCPCC_PUBLIC_PORT}",
                    "--backend",
                    f"127.0.0.1:{TCPCC_BACKEND_PORT}",
                    "--cc",
                    "bbr",
                    "--kernel",
                    str(kernel),
                    "--firewall-backend",
                    "nft-lib",
                    "--tun-name",
                    names["tun_name"],
                    "--max-connections",
                    "8",
                    "--shutdown-grace-period",
                    "5",
                ),
                stdout=event_stream,
                stderr=diagnostic_stream,
                start_new_session=True,
            )
        finally:
            event_stream.close()
            diagnostic_stream.close()
        tcpcc_ready = wait_tcpcc_ready(event_path, tcpcc_process)

        for round_index in range(scenario.repetitions):
            order = CASES[round_index:] + CASES[:round_index]
            for order_index, case in enumerate(order):
                measurement = run_iperf_measurement(
                    names,
                    scenario,
                    output_dir,
                    case=case,
                    round_number=round_index + 1,
                    order=order_index + 1,
                )
                measurements[case].append(measurement)
                time.sleep(scenario.settle_seconds)

        tcpcc_process.send_signal(signal.SIGTERM)
        tcpcc_status = tcpcc_process.wait(timeout=20)
        if tcpcc_status != 0:
            raise RuntimeError(f"tcpcc exited with status {tcpcc_status}")
        write_text(output_dir / "qdisc-after.txt", qdisc_report(names))
        qdisc = collect_qdisc_observations(names, scenario)
        events = read_events(event_path)
        tcpcc_contract = validate_tcpcc_events(events, scenario)
        assert_tcpcc_resources_removed(names, tcpcc_contract["ready"])

        summaries, checks, passed = summarize_measurements(
            measurements,
            scenario,
        )
        checks.extend(
            (
                {
                    "name": "observed_rtt_reflects_scenario",
                    "gate": True,
                    "passed": True,
                    "observed": ping["average_ms"],
                    "expected": {
                        "configured_rtt_ms": scenario.rtt_ms,
                        "tolerance": "70%-150%",
                    },
                },
                {
                    "name": "tcpcc_public_connections_inherited_bbr",
                    "gate": True,
                    "passed": tcpcc_contract["accepted_cc"] == "bbr",
                    "observed": tcpcc_contract["accepted_cc"],
                    "expected": "bbr",
                },
                {
                    "name": "tcpcc_clean_shutdown",
                    "gate": True,
                    "passed": tcpcc_contract["clean_stop"] is True,
                    "observed": tcpcc_contract["clean_stop"],
                    "expected": True,
                },
            )
        )
        for direction in ("ack_direction", "data_direction"):
            observed_loss = qdisc[direction]["observed_drop_percent"]
            checks.append(
                {
                    "name": f"{direction}_netem_loss_observed",
                    "gate": True,
                    "passed": (
                        0.2 * scenario.random_loss_percent
                        <= observed_loss
                        <= 5 * scenario.random_loss_percent
                    ),
                    "observed": observed_loss,
                    "expected": {
                        "configured_percent": scenario.random_loss_percent,
                        "minimum": 0.2 * scenario.random_loss_percent,
                        "maximum": 5 * scenario.random_loss_percent,
                    },
                }
            )
        for endpoint in ("server_endpoint", "client_endpoint"):
            checks.append(
                {
                    "name": f"{endpoint}_fq_without_drops",
                    "gate": True,
                    "passed": qdisc[endpoint]["drops"] == 0,
                    "observed": qdisc[endpoint]["drops"],
                    "expected": 0,
                }
            )
        passed = passed and all(
            check["passed"] for check in checks if check["gate"]
        )
        report = {
            "schema_version": 1,
            "scenario_id": scenario.scenario_id,
            "scenario": scenario.raw,
            "derived_network": {
                "configured_rtt_ms": scenario.rtt_ms,
                "configured_bdp_bytes": scenario.bdp_bytes,
            },
            "environment": environment,
            "ping": ping,
            "qdisc": qdisc,
            "measurements": measurements,
            "summaries": summaries,
            "tcpcc_runtime": tcpcc_contract,
            "checks": checks,
            "passed": passed,
        }
        write_text(
            output_dir / "report.json",
            json.dumps(report, indent=2, sort_keys=True) + "\n",
        )
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        if not passed:
            raise RuntimeError("high-BDP iperf acceptance checks failed")
        return 0
    finally:
        stop_process(tcpcc_process)
        stop_process(backend_server)
        stop_process(native_server)
        for namespace in reversed(namespaces):
            run(["ip", "netns", "delete", namespace], check=False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--integration", action="store_true")
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument(
        "--scenario-file",
        type=Path,
        default=DEFAULT_SCENARIO,
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.integration:
        raise ValueError("refusing privileged setup without --integration")
    try:
        return benchmark(args)
    except BaseException as error:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        write_text(
            args.output_dir / "failure.txt",
            "".join(traceback.format_exception(error)),
        )
        print(f"tcpcc high-BDP iperf benchmark failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

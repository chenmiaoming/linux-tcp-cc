#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the read-only M8.3 host prerequisite preflight."""

from __future__ import annotations

import json
import os
import stat
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from tcpcc_host import HostInspector, collect_preflight  # noqa: E402


class RecordingFixture:
    def __init__(self) -> None:
        self.proc_root = Path("/fixture/proc")
        self.dev_root = Path("/fixture/dev")
        self.operations: list[tuple[str, str]] = []
        self.values: dict[str, str | BaseException] = {
            "self/status": "Name:\ttcpcc-test\nCapEff:\t0000000000001000\n",
            "sys/net/ipv4/ip_forward": "1\n",
            "sys/net/ipv4/tcp_congestion_control": "bbr\n",
            "sys/net/ipv4/tcp_available_congestion_control": "reno cubic bbr\n",
            "sys/net/ipv4/conf/all/rp_filter": "0\n",
            "sys/net/ipv4/conf/default/rp_filter": "0\n",
        }
        self.tools: dict[str, str | None] = {
            "ip": "/usr/sbin/ip",
            "nft": "/usr/sbin/nft",
        }
        self.tun_kind = "character"
        self.tun_access = True

    def reader(self, path: Path) -> str:
        relative = str(path.relative_to(self.proc_root))
        self.operations.append(("read", relative))
        value = self.values.get(relative, FileNotFoundError(relative))
        if isinstance(value, BaseException):
            raise value
        return value

    def resolver(self, name: str) -> str | None:
        self.operations.append(("resolve", name))
        return self.tools.get(name)

    def statter(self, path: Path) -> os.stat_result:
        relative = str(path.relative_to(self.dev_root))
        self.operations.append(("stat", relative))
        if self.tun_kind == "missing":
            raise FileNotFoundError(relative)
        file_type = stat.S_IFCHR if self.tun_kind == "character" else stat.S_IFREG
        return os.stat_result((file_type | 0o660, 0, 0, 1, 0, 0, 0, 0, 0, 0))

    def access(self, path: Path, mode: int) -> bool:
        relative = str(path.relative_to(self.dev_root))
        self.operations.append(("access", f"{relative}:{mode}"))
        return self.tun_access

    def inspector(self) -> HostInspector:
        return HostInspector(
            proc_root=self.proc_root,
            dev_root=self.dev_root,
            reader=self.reader,
            resolver=self.resolver,
            statter=self.statter,
            access=self.access,
        )


def checks_by_id(report) -> dict[str, object]:
    return {check.check_id: check for check in report.checks}


class HostPreflightTests(unittest.TestCase):
    def test_all_green_report_is_stable_and_machine_readable(self) -> None:
        fixture = RecordingFixture()
        report = collect_preflight("bbr", fixture.inspector())

        self.assertTrue(report.ok)
        self.assertEqual(
            [check.check_id for check in report.checks],
            [
                "cap.net_admin",
                "device.tun",
                "tool.ip",
                "tool.nft",
                "sysctl.ipv4_forward",
                "sysctl.tcp_congestion_control",
                "sysctl.tcp_available_congestion_control",
                "sysctl.rp_filter.all",
                "sysctl.rp_filter.default",
            ],
        )
        self.assertTrue(all(check.status == "pass" for check in report.checks))
        decoded = json.loads(report.to_json())
        self.assertEqual(decoded["schema"], "tcpcc.host-preflight.v1")
        self.assertEqual(decoded["requested_cc"], "bbr")
        self.assertTrue(decoded["ok"])
        self.assertEqual(report.to_json(), report.to_json())

    def test_required_failures_are_aggregated_with_remediation(self) -> None:
        fixture = RecordingFixture()
        fixture.values["self/status"] = "CapEff:\t0000000000000000\n"
        fixture.values["sys/net/ipv4/ip_forward"] = "0\n"
        fixture.values["sys/net/ipv4/tcp_congestion_control"] = "cubic\n"
        fixture.values["sys/net/ipv4/tcp_available_congestion_control"] = (
            "reno cubic\n"
        )
        fixture.tun_kind = "missing"
        fixture.tools = {"ip": None, "nft": None}

        report = collect_preflight("bbr", fixture.inspector())
        failed = [check for check in report.checks if check.status == "fail"]

        self.assertFalse(report.ok)
        self.assertEqual(
            {check.check_id for check in failed},
            {
                "cap.net_admin",
                "device.tun",
                "tool.ip",
                "tool.nft",
                "sysctl.ipv4_forward",
                "sysctl.tcp_congestion_control",
                "sysctl.tcp_available_congestion_control",
            },
        )
        self.assertTrue(all(check.remediation for check in failed))

    def test_rp_filter_is_advisory_and_never_fails_report(self) -> None:
        fixture = RecordingFixture()
        fixture.values["sys/net/ipv4/conf/all/rp_filter"] = "1\n"
        fixture.values["sys/net/ipv4/conf/default/rp_filter"] = "2\n"

        report = collect_preflight("bbr", fixture.inspector())
        checks = checks_by_id(report)

        self.assertTrue(report.ok)
        self.assertEqual(checks["sysctl.rp_filter.all"].status, "warn")
        self.assertEqual(checks["sysctl.rp_filter.default"].status, "warn")
        self.assertEqual(checks["sysctl.rp_filter.all"].severity, "advisory")

    def test_unreadable_and_malformed_proc_values_are_attributable(self) -> None:
        fixture = RecordingFixture()
        fixture.values["self/status"] = "Name:\ttcpcc-test\n"
        fixture.values["sys/net/ipv4/ip_forward"] = "\n"
        fixture.values["sys/net/ipv4/tcp_congestion_control"] = PermissionError()
        fixture.values["sys/net/ipv4/tcp_available_congestion_control"] = "\x00"

        checks = checks_by_id(collect_preflight("bbr", fixture.inspector()))

        self.assertEqual(checks["cap.net_admin"].observed, "malformed")
        self.assertEqual(checks["sysctl.ipv4_forward"].observed, "malformed")
        self.assertEqual(
            checks["sysctl.tcp_congestion_control"].observed,
            "unreadable",
        )
        self.assertEqual(
            checks["sysctl.tcp_available_congestion_control"].observed,
            "malformed",
        )

    def test_tun_must_be_character_device_with_read_write_access(self) -> None:
        fixture = RecordingFixture()
        fixture.tun_kind = "regular"
        checks = checks_by_id(collect_preflight("bbr", fixture.inspector()))
        self.assertEqual(checks["device.tun"].observed, "not-a-character-device")

        fixture = RecordingFixture()
        fixture.tun_access = False
        checks = checks_by_id(collect_preflight("bbr", fixture.inspector()))
        self.assertEqual(
            checks["device.tun"].observed,
            "character-device-without-read-write-access",
        )

    def test_requested_cc_name_is_bounded_before_host_inspection(self) -> None:
        fixture = RecordingFixture()
        for invalid in ("", "BBR", "bbr.v3", "x" * 16, "bbr v2"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    collect_preflight(invalid, fixture.inspector())
        self.assertEqual(fixture.operations, [])

    def test_preflight_performs_only_read_stat_access_and_resolve(self) -> None:
        fixture = RecordingFixture()
        collect_preflight("bbr", fixture.inspector())

        operation_kinds = {kind for kind, _ in fixture.operations}
        self.assertEqual(operation_kinds, {"read", "stat", "access", "resolve"})
        self.assertEqual(
            [value for kind, value in fixture.operations if kind == "resolve"],
            ["ip", "nft"],
        )
        self.assertNotIn("write", operation_kinds)
        self.assertNotIn("command", operation_kinds)


if __name__ == "__main__":
    unittest.main(verbosity=2)

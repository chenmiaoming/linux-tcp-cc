#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-only host prerequisite inspection for the tcpcc network lifecycle."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

CAP_NET_ADMIN = 12
CC_NAME = re.compile(r"[a-z0-9_-]{1,15}\Z")

Reader = Callable[[Path], str]
Resolver = Callable[[str], str | None]
Statter = Callable[[Path], os.stat_result]
AccessChecker = Callable[[Path, int], bool]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="ascii")


def _stat_path(path: Path) -> os.stat_result:
    return path.stat()


def _access_path(path: Path, mode: int) -> bool:
    return os.access(path, mode)


@dataclass(frozen=True)
class CheckResult:
    """One stable preflight check result."""

    check_id: str
    status: str
    severity: str
    observed: str
    expected: str
    remediation: str

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.check_id,
            "status": self.status,
            "severity": self.severity,
            "observed": self.observed,
            "expected": self.expected,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class PreflightReport:
    """Deterministic aggregate report consumed by later lifecycle stages."""

    requested_cc: str
    checks: tuple[CheckResult, ...]

    @property
    def ok(self) -> bool:
        return all(check.status != "fail" for check in self.checks)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "tcpcc.host-preflight.v1",
            "ok": self.ok,
            "requested_cc": self.requested_cc,
            "checks": [check.as_dict() for check in self.checks],
        }

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )


class HostInspector:
    """Injectable, read-only view of procfs, devices, and executable lookup."""

    def __init__(
        self,
        *,
        proc_root: Path = Path("/proc"),
        dev_root: Path = Path("/dev"),
        reader: Reader = _read_text,
        resolver: Resolver = shutil.which,
        statter: Statter = _stat_path,
        access: AccessChecker = _access_path,
    ) -> None:
        self.proc_root = proc_root
        self.dev_root = dev_root
        self.reader = reader
        self.resolver = resolver
        self.statter = statter
        self.access = access

    def read_proc(self, relative: str) -> tuple[str | None, str | None]:
        path = self.proc_root / relative
        try:
            value = self.reader(path).strip()
        except FileNotFoundError:
            return None, "missing"
        except PermissionError:
            return None, "unreadable"
        except (OSError, UnicodeError):
            return None, "unreadable"
        if not value or "\x00" in value:
            return None, "malformed"
        return value, None


def _check(
    check_id: str,
    passed: bool,
    severity: str,
    observed: str,
    expected: str,
    remediation: str,
) -> CheckResult:
    if passed:
        status = "pass"
    elif severity == "advisory":
        status = "warn"
    else:
        status = "fail"
    return CheckResult(
        check_id,
        status,
        severity,
        observed,
        expected,
        "" if passed else remediation,
    )


def _cap_net_admin(inspector: HostInspector) -> CheckResult:
    value, error = inspector.read_proc("self/status")
    enabled = False
    observed = error or "malformed"
    if value is not None:
        match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)\s*$", value, re.MULTILINE)
        if match is not None:
            mask = int(match.group(1), 16)
            enabled = bool(mask & (1 << CAP_NET_ADMIN))
            observed = f"0x{mask:x}"
    return _check(
        "cap.net_admin",
        enabled,
        "required",
        observed,
        "effective CAP_NET_ADMIN bit 12",
        "run tcpcc with CAP_NET_ADMIN, normally via sudo or a container capability",
    )


def _tun_device(inspector: HostInspector) -> CheckResult:
    path = inspector.dev_root / "net/tun"
    observed = "missing"
    usable = False
    try:
        device_stat = inspector.statter(path)
        is_character = stat.S_ISCHR(device_stat.st_mode)
        has_access = inspector.access(path, os.R_OK | os.W_OK)
        usable = is_character and has_access
        if not is_character:
            observed = "not-a-character-device"
        elif not has_access:
            observed = "character-device-without-read-write-access"
        else:
            observed = "character-device-with-read-write-access"
    except FileNotFoundError:
        pass
    except PermissionError:
        observed = "unreadable"
    except OSError:
        observed = "unreadable"
    return _check(
        "device.tun",
        usable,
        "required",
        observed,
        "/dev/net/tun character device with read/write access",
        "enable TUN for the container and grant tcpcc read/write access to /dev/net/tun",
    )


def _tool(inspector: HostInspector, name: str, remediation: str) -> CheckResult:
    try:
        resolved = inspector.resolver(name)
    except OSError:
        resolved = None
    return _check(
        f"tool.{name}",
        resolved is not None,
        "required",
        resolved or "missing",
        f"{name} executable on PATH",
        remediation,
    )


def _required_sysctl(
    inspector: HostInspector,
    check_id: str,
    relative: str,
    expected: str,
    remediation: str,
) -> CheckResult:
    value, error = inspector.read_proc(relative)
    return _check(
        check_id,
        value == expected,
        "required",
        value if value is not None else error or "unreadable",
        expected,
        remediation,
    )


def _available_cc(inspector: HostInspector, requested_cc: str) -> CheckResult:
    value, error = inspector.read_proc(
        "sys/net/ipv4/tcp_available_congestion_control"
    )
    available = value.split() if value is not None else []
    return _check(
        "sysctl.tcp_available_congestion_control",
        requested_cc in available,
        "required",
        " ".join(available) if available else error or "malformed",
        f"list containing {requested_cc}",
        f"make {requested_cc} available on the host before starting tcpcc",
    )


def _rp_filter(inspector: HostInspector, scope: str) -> CheckResult:
    value, error = inspector.read_proc(
        f"sys/net/ipv4/conf/{scope}/rp_filter"
    )
    return _check(
        f"sysctl.rp_filter.{scope}",
        value == "0",
        "advisory",
        value if value is not None else error or "unreadable",
        "0",
        "review reverse-path filtering for the routed TUN path; tcpcc will not change it",
    )


def collect_preflight(
    requested_cc: str,
    inspector: HostInspector | None = None,
) -> PreflightReport:
    """Collect every prerequisite without mutating the inspected host."""

    if CC_NAME.fullmatch(requested_cc) is None:
        raise ValueError(
            "requested congestion-control name must contain 1-15 lowercase "
            "letters, digits, underscores, or hyphens"
        )
    if inspector is None:
        inspector = HostInspector()

    checks = (
        _cap_net_admin(inspector),
        _tun_device(inspector),
        _tool(
            inspector,
            "ip",
            "install iproute2 and expose the ip executable on PATH",
        ),
        _tool(
            inspector,
            "nft",
            "install nftables and expose the nft executable on PATH",
        ),
        _required_sysctl(
            inspector,
            "sysctl.ipv4_forward",
            "sys/net/ipv4/ip_forward",
            "1",
            "set net.ipv4.ip_forward=1 before starting tcpcc",
        ),
        _required_sysctl(
            inspector,
            "sysctl.tcp_congestion_control",
            "sys/net/ipv4/tcp_congestion_control",
            requested_cc,
            f"set net.ipv4.tcp_congestion_control={requested_cc} before starting tcpcc",
        ),
        _available_cc(inspector, requested_cc),
        _rp_filter(inspector, "all"),
        _rp_filter(inspector, "default"),
    )
    return PreflightReport(requested_cc=requested_cc, checks=checks)

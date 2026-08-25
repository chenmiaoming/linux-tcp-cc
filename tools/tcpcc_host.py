#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host prerequisite inspection and owned tcpcc network lifecycle primitives."""

from __future__ import annotations

import errno
import fcntl
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

CAP_NET_ADMIN = 12
CC_NAME = re.compile(r"[a-z0-9_-]{1,15}\Z")
TUN_NAME = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
NFT_TABLE_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")

# Linux UAPI values from include/uapi/linux/if_tun.h. IFF_TUN_EXCL makes
# creation atomic: TUNSETIFF must not attach this fd to a pre-existing device.
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
IFF_TUN_EXCL = 0x8000
TUN_IFF_FLAGS = IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL
IFNAMSIZ = 16
IFREQ_SIZE = 40
DEFAULT_TUN_PATH = Path("/dev/net/tun")
DEFAULT_TUN_MTU = 1500
MIN_IPV4_MTU = 68
MAX_IPV4_MTU = 65535
DEFAULT_NAME_ATTEMPTS = 8

Reader = Callable[[Path], str]
Resolver = Callable[[str], str | None]
Statter = Callable[[Path], os.stat_result]
AccessChecker = Callable[[Path, int], bool]
TunOpener = Callable[[str, int], int]
TunIoctl = Callable[[int, int, bytearray, bool], object]
TunCloser = Callable[[int], None]
CommandRunner = Callable[[list[str]], None]
NameFactory = Callable[[], str]
CleanupCallback = Callable[[], None]
NftRunner = Callable[[list[str], str | None], None]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="ascii")


def _stat_path(path: Path) -> os.stat_result:
    return path.stat()


def _access_path(path: Path, mode: int) -> bool:
    return os.access(path, mode)


def _run_command(argv: list[str]) -> None:
    subprocess.run(
        argv,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _new_tun_name() -> str:
    # Five random bytes keep the complete name within Linux's 15-byte limit.
    return f"tcpcc{secrets.token_hex(5)}"


def _run_nft(argv: list[str], input_text: str | None) -> None:
    subprocess.run(
        argv,
        input=input_text,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _new_nft_table_name() -> str:
    return f"tcpcc_{secrets.token_hex(6)}"


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


def _validate_tun_name(name: str) -> str:
    if (
        not isinstance(name, str)
        or TUN_NAME.fullmatch(name) is None
        or name in {".", ".."}
    ):
        raise ValueError(
            "TUN name must contain 1-15 ASCII letters, digits, dots, "
            "underscores, or hyphens"
        )
    return name


@dataclass(frozen=True)
class TunConfig:
    """Validated point-to-point IPv4 configuration for one TUN queue."""

    host_address: str
    guest_address: str
    mtu: int = DEFAULT_TUN_MTU
    name: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.host_address, str):
            raise ValueError("host_address must be one IPv4 address")
        if not isinstance(self.guest_address, str):
            raise ValueError("guest_address must be one IPv4 address")
        try:
            host = str(ipaddress.IPv4Address(self.host_address))
        except (ipaddress.AddressValueError, TypeError) as error:
            raise ValueError("host_address must be one IPv4 address") from error
        try:
            guest = str(ipaddress.IPv4Address(self.guest_address))
        except (ipaddress.AddressValueError, TypeError) as error:
            raise ValueError("guest_address must be one IPv4 address") from error
        if host == guest:
            raise ValueError("host_address and guest_address must be different")
        if (
            isinstance(self.mtu, bool)
            or not isinstance(self.mtu, int)
            or not MIN_IPV4_MTU <= self.mtu <= MAX_IPV4_MTU
        ):
            raise ValueError(
                f"TUN MTU must be an integer from {MIN_IPV4_MTU} "
                f"through {MAX_IPV4_MTU}"
            )
        if self.name is not None:
            _validate_tun_name(self.name)
        object.__setattr__(self, "host_address", host)
        object.__setattr__(self, "guest_address", guest)


@dataclass(frozen=True)
class CleanupFailure:
    """One failed cleanup callback, retained for operator diagnostics."""

    label: str
    error: Exception


class CleanupError(RuntimeError):
    """Aggregate raised after every owned resource has been attempted."""

    def __init__(self, failures: tuple[CleanupFailure, ...]) -> None:
        self.failures = failures
        details = "; ".join(
            f"{failure.label}: {type(failure.error).__name__}: {failure.error}"
            for failure in failures
        )
        super().__init__(f"resource cleanup failed: {details}")


class TunSetupCleanupError(RuntimeError):
    """Report both a setup error and failure to close its temporary fd."""

    def __init__(
        self,
        setup_error: BaseException,
        cleanup_error: BaseException,
    ) -> None:
        self.setup_error = setup_error
        self.cleanup_error = cleanup_error
        super().__init__(
            "TUN setup failed and its queue fd could not be closed: "
            f"setup={type(setup_error).__name__}: {setup_error}; "
            f"cleanup={type(cleanup_error).__name__}: {cleanup_error}"
        )


class OwnershipJournal:
    """Own cleanup callbacks and execute each exactly once in reverse order."""

    def __init__(self) -> None:
        self._entries: list[tuple[str, CleanupCallback]] = []
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def defer(self, label: str, callback: CleanupCallback) -> None:
        if self._closed:
            raise RuntimeError("cannot add a resource to a closed journal")
        if not label:
            raise ValueError("cleanup label must not be empty")
        self._entries.append((label, callback))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        entries = self._entries
        self._entries = []
        failures: list[CleanupFailure] = []
        for label, callback in reversed(entries):
            try:
                callback()
            except Exception as error:
                failures.append(CleanupFailure(label, error))
        if failures:
            raise CleanupError(tuple(failures))


class TunQueue:
    """The open fd whose lifetime owns a newly created nonpersistent TUN."""

    def __init__(self, name: str, fd: int, closer: TunCloser) -> None:
        self.name = name
        self._fd: int | None = fd
        self._closer = closer

    @property
    def fd(self) -> int:
        if self._fd is None:
            raise ValueError("TUN queue is closed")
        return self._fd

    def fileno(self) -> int:
        return self.fd

    @property
    def closed(self) -> bool:
        return self._fd is None

    def close(self) -> None:
        if self._fd is None:
            return
        fd = self._fd
        self._fd = None
        self._closer(fd)


def _ifreq(name: str) -> bytearray:
    request = bytearray(IFREQ_SIZE)
    struct.pack_into(
        "16sH",
        request,
        0,
        name.encode("ascii"),
        TUN_IFF_FLAGS,
    )
    return request


def _attached_name(request: bytearray) -> str:
    encoded = bytes(request[:IFNAMSIZ]).split(b"\0", 1)[0]
    try:
        return encoded.decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError("TUNSETIFF returned a non-ASCII interface name") from error


def _close_after_setup_error(
    fd: int,
    closer: TunCloser,
    setup_error: BaseException,
) -> None:
    try:
        closer(fd)
    except BaseException as cleanup_error:
        raise TunSetupCleanupError(setup_error, cleanup_error) from setup_error


def create_tun_queue(
    config: TunConfig,
    *,
    tun_path: Path = DEFAULT_TUN_PATH,
    ip_path: str = "ip",
    opener: TunOpener = os.open,
    ioctl: TunIoctl = fcntl.ioctl,
    closer: TunCloser = os.close,
    runner: CommandRunner = _run_command,
    name_factory: NameFactory = _new_tun_name,
    max_name_attempts: int = DEFAULT_NAME_ATTEMPTS,
) -> TunQueue:
    """Create, configure, and return one exclusively owned TUN queue.

    No persistent interface is created. Closing the returned fd is the sole
    normal cleanup operation and causes Linux to remove the interface together
    with its attached address and route state.
    """

    if not isinstance(config, TunConfig):
        raise TypeError("config must be a TunConfig")
    if not isinstance(ip_path, str) or not ip_path or "\0" in ip_path:
        raise ValueError("ip_path must name one executable")
    if (
        isinstance(max_name_attempts, bool)
        or not isinstance(max_name_attempts, int)
        or max_name_attempts < 1
    ):
        raise ValueError("max_name_attempts must be a positive integer")

    generated = config.name is None
    attempts = max_name_attempts if generated else 1
    last_collision: OSError | None = None
    open_flags = os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC

    for _ in range(attempts):
        name = _validate_tun_name(name_factory() if generated else config.name or "")
        fd = opener(str(tun_path), open_flags)
        name_collision = False
        try:
            request = _ifreq(name)
            try:
                ioctl(fd, TUNSETIFF, request, True)
            except OSError as ioctl_error:
                if (
                    generated
                    and ioctl_error.errno in {errno.EBUSY, errno.EEXIST}
                ):
                    last_collision = ioctl_error
                    name_collision = True
                raise
            actual_name = _attached_name(request)
            if actual_name != name:
                raise RuntimeError(
                    f"TUNSETIFF attached {actual_name!r}, expected {name!r}"
                )
            runner(
                [
                    ip_path,
                    "address",
                    "add",
                    f"{config.host_address}/32",
                    "peer",
                    f"{config.guest_address}/32",
                    "dev",
                    name,
                ]
            )
            runner(
                [
                    ip_path,
                    "link",
                    "set",
                    "dev",
                    name,
                    "mtu",
                    str(config.mtu),
                    "up",
                ]
            )
        except BaseException as setup_error:
            _close_after_setup_error(fd, closer, setup_error)
            if name_collision:
                continue
            raise
        return TunQueue(actual_name, fd, closer)

    raise FileExistsError(
        errno.EEXIST,
        f"could not allocate a unique TUN name after {attempts} attempts",
    ) from last_collision


def _validate_nft_table_name(name: str) -> str:
    if not isinstance(name, str) or NFT_TABLE_NAME.fullmatch(name) is None:
        raise ValueError(
            "nftables table name must start with a lowercase letter and "
            "contain at most 32 lowercase letters, digits, or underscores"
        )
    return name


def _validate_port(port: int, field: str) -> int:
    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise ValueError(f"{field} must be an integer from 1 through 65535")
    return port


def _validate_endpoint_address(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be one usable IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError(f"{field} must be one usable IPv4 address") from error
    if address.is_unspecified or address.is_multicast:
        raise ValueError(f"{field} must be one usable IPv4 address")
    return str(address)


@dataclass(frozen=True)
class NftDnatConfig:
    """One exact public IPv4/TCP endpoint and its hosted destination."""

    listen_address: str
    listen_port: int
    target_address: str
    target_port: int
    table_name: str | None = None

    def __post_init__(self) -> None:
        listen_address = _validate_endpoint_address(
            self.listen_address,
            "listen_address",
        )
        target_address = _validate_endpoint_address(
            self.target_address,
            "target_address",
        )
        listen_port = _validate_port(self.listen_port, "listen_port")
        target_port = _validate_port(self.target_port, "target_port")
        if listen_address == target_address:
            raise ValueError("DNAT listen and target addresses must be different")
        if self.table_name is not None:
            _validate_nft_table_name(self.table_name)
        object.__setattr__(self, "listen_address", listen_address)
        object.__setattr__(self, "listen_port", listen_port)
        object.__setattr__(self, "target_address", target_address)
        object.__setattr__(self, "target_port", target_port)


def _dnat_batch(config: NftDnatConfig, table_name: str) -> str:
    return (
        f"create table ip {table_name}\n"
        f"add chain ip {table_name} prerouting "
        "{ type nat hook prerouting priority dstnat; policy accept; }\n"
        f"add rule ip {table_name} prerouting "
        f"ip daddr {config.listen_address} "
        f"tcp dport {config.listen_port} counter "
        f"dnat to {config.target_address}:{config.target_port}\n"
    )


class NftDnatLease:
    """Exclusive ownership of one instance-scoped nftables DNAT table."""

    def __init__(
        self,
        table_name: str,
        nft_path: str,
        runner: NftRunner,
    ) -> None:
        self.table_name = table_name
        self._nft_path = nft_path
        self._runner = runner
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._runner(
            [
                self._nft_path,
                "delete",
                "table",
                "ip",
                self.table_name,
            ],
            None,
        )


def install_nft_dnat(
    config: NftDnatConfig,
    *,
    nft_path: str = "nft",
    runner: NftRunner = _run_nft,
    table_name_factory: NameFactory = _new_nft_table_name,
) -> NftDnatLease:
    """Atomically install one exact-match DNAT table and own its deletion."""

    if not isinstance(config, NftDnatConfig):
        raise TypeError("config must be an NftDnatConfig")
    if not isinstance(nft_path, str) or not nft_path or "\0" in nft_path:
        raise ValueError("nft_path must name one executable")
    table_name = _validate_nft_table_name(
        table_name_factory() if config.table_name is None else config.table_name
    )
    runner(
        [nft_path, "--file", "-"],
        _dnat_batch(config, table_name),
    )
    return NftDnatLease(table_name, nft_path, runner)

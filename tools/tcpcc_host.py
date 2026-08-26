#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host prerequisite inspection and owned tcpcc network lifecycle primitives."""

from __future__ import annotations

import errno
import ctypes
import ctypes.util
import fcntl
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

CAP_NET_ADMIN = 12
CC_NAME = re.compile(r"[a-z0-9_-]{1,15}\Z")
TUN_NAME = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
NFT_TABLE_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
NFT_OWNER_PREFIX = "tcpcc.owner."
NFT_OWNER_MARKER = re.compile(
    r"tcpcc\.owner\.v1 pid=([1-9][0-9]*) start=([1-9][0-9]*) "
    r"tun=([A-Za-z0-9_.-]{1,15})\Z"
)
FIREWALL_BACKENDS = frozenset(("nft-lib", "nft-exec", "iptables"))
IPTABLES_CHAIN_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,27}\Z")
IPTABLES_OWNED_CHAIN = re.compile(r"TCPCC_[a-f0-9]{12}\Z")
IPTABLES_CHAIN_PREFIX = "TCPCC_"
IPTABLES_JUMP_PREFIX = "tcpcc.jump."
NFT_CTX_OUTPUT_JSON = 1 << 4

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
LibraryResolver = Callable[[str], str | None]
Statter = Callable[[Path], os.stat_result]
AccessChecker = Callable[[Path, int], bool]
TunOpener = Callable[[str, int], int]
TunIoctl = Callable[[int, int, bytearray, bool], object]
TunCloser = Callable[[int], None]
CommandRunner = Callable[[list[str]], None]
NameFactory = Callable[[], str]
CleanupCallback = Callable[[], None]
NftRunner = Callable[[list[str], str | None], None]
OutputRunner = Callable[[list[str]], str]
FirewallCommandRunner = Callable[[list[str], str | None], str]


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


def _read_command(argv: list[str]) -> str:
    return subprocess.run(
        argv,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout


def _run_firewall_command(argv: list[str], input_text: str | None) -> str:
    return subprocess.run(
        argv,
        input=input_text,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout


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
        library_resolver: LibraryResolver = ctypes.util.find_library,
        statter: Statter = _stat_path,
        access: AccessChecker = _access_path,
    ) -> None:
        self.proc_root = proc_root
        self.dev_root = dev_root
        self.reader = reader
        self.resolver = resolver
        self.library_resolver = library_resolver
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


def _tool(
    inspector: HostInspector,
    name: str,
    remediation: str,
    *,
    check_name: str | None = None,
) -> CheckResult:
    try:
        resolved = inspector.resolver(name)
    except OSError:
        resolved = None
    return _check(
        f"tool.{check_name or name}",
        resolved is not None,
        "required",
        resolved or "missing",
        f"{name} executable on PATH",
        remediation,
    )


def _library(
    inspector: HostInspector,
    name: str,
    remediation: str,
) -> CheckResult:
    try:
        resolved = inspector.library_resolver(name)
    except OSError:
        resolved = None
    return _check(
        f"library.{name}",
        resolved is not None,
        "required",
        resolved or "missing",
        f"{name} shared library available to the dynamic loader",
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
    *,
    firewall_backend: str = "nft-exec",
    nft_path: str = "nft",
    iptables_path: str = "iptables",
    iptables_restore_path: str = "iptables-restore",
    iptables_save_path: str = "iptables-save",
) -> PreflightReport:
    """Collect every prerequisite without mutating the inspected host."""

    if CC_NAME.fullmatch(requested_cc) is None:
        raise ValueError(
            "requested congestion-control name must contain 1-15 lowercase "
            "letters, digits, underscores, or hyphens"
        )
    if inspector is None:
        inspector = HostInspector()

    prefix_checks = (
        _cap_net_admin(inspector),
        _tun_device(inspector),
        _tool(
            inspector,
            "ip",
            "install iproute2 and expose the ip executable on PATH",
        ),
    )

    if firewall_backend == "nft-exec":
        firewall_checks = (
            _tool(
                inspector,
                nft_path,
                f"install nftables and expose {nft_path} on PATH",
                check_name="nft",
            ),
        )
    elif firewall_backend == "nft-lib":
        firewall_checks = (
            _library(
                inspector,
                "nftables",
                "install the libnftables shared library",
            ),
        )
    elif firewall_backend == "iptables":
        firewall_checks = tuple(
            _tool(
                inspector,
                command,
                f"install iptables and expose {command} on PATH",
                check_name=check_name,
            )
            for command, check_name in (
                (iptables_path, "iptables"),
                (iptables_restore_path, "iptables-restore"),
                (iptables_save_path, "iptables-save"),
            )
        )
    else:
        raise ValueError(
            "firewall_backend must be one of: "
            + ", ".join(sorted(FIREWALL_BACKENDS))
        )

    checks = (
        *prefix_checks,
        *firewall_checks,
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
    error: BaseException


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
            except BaseException as error:
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


@dataclass(frozen=True)
class NftOwnership:
    """Versioned process identity stored on an instance-owned DNAT rule."""

    pid: int
    start_time: int
    tun_name: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.pid, "pid"),
            (self.start_time, "start_time"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"nftables ownership {field} must be positive")
        _validate_tun_name(self.tun_name)

    def marker(self) -> str:
        return (
            f"tcpcc.owner.v1 pid={self.pid} start={self.start_time} "
            f"tun={self.tun_name}"
        )


@dataclass(frozen=True)
class NftOwnershipObservation:
    """Classification of one table carrying a tcpcc ownership marker."""

    table_name: str
    status: str
    owner_pid: int | None
    owner_start_time: int | None
    tun_name: str | None
    detail: str
    remediation: str

    def as_dict(self) -> dict[str, object]:
        return {
            "table": self.table_name,
            "status": self.status,
            "owner_pid": self.owner_pid,
            "owner_start_time": self.owner_start_time,
            "tun": self.tun_name,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class NftOwnershipReport:
    """Stable read-only stale-resource report collected before acquisition."""

    observations: tuple[NftOwnershipObservation, ...]

    @property
    def blocking(self) -> bool:
        return any(item.status != "active" for item in self.observations)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "tcpcc.nft-ownership.v1",
            "blocking": self.blocking,
            "tables": [item.as_dict() for item in self.observations],
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))


def _process_start_time(
    pid: int,
    *,
    proc_root: Path = Path("/proc"),
    reader: Reader = _read_text,
) -> int:
    value = reader(proc_root / str(pid) / "stat").strip()
    closing = value.rfind(")")
    if closing < 0:
        raise ValueError("process stat has no command terminator")
    fields = value[closing + 1 :].split()
    # The first field after the command is field 3; starttime is field 22.
    if len(fields) <= 19:
        raise ValueError("process stat has no start-time field")
    start_time = int(fields[19])
    if start_time < 1:
        raise ValueError("process start time is not positive")
    return start_time


def current_nft_ownership(
    tun_name: str,
    *,
    proc_root: Path = Path("/proc"),
    reader: Reader = _read_text,
    pid_provider: Callable[[], int] = os.getpid,
) -> NftOwnership:
    """Build an identity robust against PID reuse from procfs start time."""

    pid = pid_provider()
    return NftOwnership(
        pid=pid,
        start_time=_process_start_time(pid, proc_root=proc_root, reader=reader),
        tun_name=tun_name,
    )


def inspect_nft_ownership(
    *,
    nft_path: str = "nft",
    runner: OutputRunner = _read_command,
    proc_root: Path = Path("/proc"),
    reader: Reader = _read_text,
) -> NftOwnershipReport:
    """Classify marked tables without changing or adopting any of them."""

    if not isinstance(nft_path, str) or not nft_path or "\0" in nft_path:
        raise ValueError("nft_path must name one executable")
    raw = runner([nft_path, "--json", "list", "ruleset", "ip"])
    try:
        document = json.loads(raw)
        entries = document["nftables"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise RuntimeError("nftables returned malformed ruleset JSON") from error
    if not isinstance(entries, list):
        raise RuntimeError("nftables returned malformed ruleset JSON")

    observations: list[NftOwnershipObservation] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        rule = entry.get("rule")
        if not isinstance(rule, dict) or rule.get("family") != "ip":
            continue
        comment = rule.get("comment")
        if not isinstance(comment, str) or not comment.startswith(NFT_OWNER_PREFIX):
            continue
        table_name = rule.get("table")
        match = NFT_OWNER_MARKER.fullmatch(comment)
        if (
            not isinstance(table_name, str)
            or NFT_TABLE_NAME.fullmatch(table_name) is None
            or match is None
        ):
            safe_table = (
                table_name
                if isinstance(table_name, str)
                and NFT_TABLE_NAME.fullmatch(table_name) is not None
                else None
            )
            remediation = "inspect the complete nftables ruleset manually"
            if safe_table is not None:
                remediation = (
                    f"inspect with: nft list table ip {safe_table}; after verifying "
                    f"ownership, remove with: nft delete table ip {safe_table}"
                )
            observations.append(
                NftOwnershipObservation(
                    table_name=(
                        table_name if isinstance(table_name, str) else "malformed"
                    ),
                    status="malformed",
                    owner_pid=None,
                    owner_start_time=None,
                    tun_name=None,
                    detail="unsupported or malformed tcpcc ownership marker",
                    remediation=remediation,
                )
            )
            continue

        pid = int(match.group(1))
        expected_start = int(match.group(2))
        tun_name = match.group(3)
        status = "stale"
        detail = "owner process is absent"
        try:
            actual_start = _process_start_time(
                pid,
                proc_root=proc_root,
                reader=reader,
            )
        except FileNotFoundError:
            pass
        except (OSError, UnicodeError, ValueError):
            detail = "owner process identity is unreadable"
        else:
            if actual_start == expected_start:
                status = "active"
                detail = "owner pid and process start time match"
            else:
                detail = "owner pid was reused by a different process"

        remediation = ""
        if status == "stale":
            remediation = (
                "verify the recorded owner is gone, then run: "
                f"nft delete table ip {table_name}"
            )
        observations.append(
            NftOwnershipObservation(
                table_name=table_name,
                status=status,
                owner_pid=pid,
                owner_start_time=expected_start,
                tun_name=tun_name,
                detail=detail,
                remediation=remediation,
            )
        )

    observations.sort(key=lambda item: item.table_name)
    return NftOwnershipReport(tuple(observations))


def _dnat_batch(
    config: NftDnatConfig,
    table_name: str,
    ownership: NftOwnership | None,
) -> str:
    owner_comment = ""
    if ownership is not None:
        owner_comment = f' comment "{ownership.marker()}"'
    return (
        f"create table ip {table_name}\n"
        f"add chain ip {table_name} prerouting "
        "{ type nat hook prerouting priority dstnat; policy accept; }\n"
        f"add rule ip {table_name} prerouting "
        f"ip daddr {config.listen_address} "
        f"tcp dport {config.listen_port} counter "
        f"dnat to {config.target_address}:{config.target_port}"
        f"{owner_comment}\n"
    )


class NftCompatibilityError(RuntimeError):
    """The host rejected a dry-run of the exact nftables transaction."""

    def __init__(self, error: subprocess.CalledProcessError) -> None:
        self.command_error = error
        detail = (error.stderr or "nftables rejected the dry-run").strip()
        super().__init__(
            "host nftables cannot install tcpcc exact DNAT and ownership "
            f"metadata: {detail}"
        )


def check_nft_dnat_compatibility(
    config: NftDnatConfig,
    *,
    ownership: NftOwnership,
    nft_path: str = "nft",
    runner: NftRunner = _run_nft,
    table_name_factory: NameFactory = _new_nft_table_name,
) -> None:
    """Ask nft/kernel to validate the full batch without applying it."""

    if not isinstance(config, NftDnatConfig):
        raise TypeError("config must be an NftDnatConfig")
    if not isinstance(ownership, NftOwnership):
        raise TypeError("ownership must be an NftOwnership")
    if not isinstance(nft_path, str) or not nft_path or "\0" in nft_path:
        raise ValueError("nft_path must name one executable")
    table_name = _validate_nft_table_name(table_name_factory())
    try:
        runner(
            [nft_path, "--check", "--file", "-"],
            _dnat_batch(config, table_name, ownership),
        )
    except subprocess.CalledProcessError as error:
        raise NftCompatibilityError(error) from error


class NftDnatLease:
    """Exclusive ownership of one instance-scoped nftables DNAT table."""

    def __init__(
        self,
        table_name: str,
        nft_path: str,
        runner: NftRunner,
        backend_id: str = "nft-exec",
    ) -> None:
        self.table_name = table_name
        self.backend_id = backend_id
        self._nft_path = nft_path
        self._runner = runner
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def resource_name(self) -> str:
        return self.table_name

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
    ownership: NftOwnership | None = None,
    backend_id: str = "nft-exec",
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
        _dnat_batch(config, table_name, ownership),
    )
    return NftDnatLease(table_name, nft_path, runner, backend_id)


class FirewallDnatLease(Protocol):
    """Resource lease returned by any packet-steering backend."""

    backend_id: str

    @property
    def resource_name(self) -> str: ...

    @property
    def closed(self) -> bool: ...

    def close(self) -> None: ...


class FirewallBackend(Protocol):
    """Structured lifecycle boundary shared by every firewall transport."""

    backend_id: str

    def inspect_ownership(self) -> NftOwnershipReport: ...

    def check_compatibility(self, config: NftDnatConfig) -> None: ...

    def install(
        self,
        config: NftDnatConfig,
        ownership: NftOwnership,
    ) -> FirewallDnatLease: ...


class NftTransport(Protocol):
    """One way of submitting the common nftables command buffer."""

    backend_id: str
    command_name: str

    def run(self, argv: list[str], input_text: str | None) -> None: ...

    def read(self, argv: list[str]) -> str: ...


class NftExecTransport:
    """Docker-style nft subprocess transport with argv and stdin only."""

    backend_id = "nft-exec"

    def __init__(
        self,
        nft_path: str = "nft",
        *,
        runner: FirewallCommandRunner = _run_firewall_command,
    ) -> None:
        if not isinstance(nft_path, str) or not nft_path or "\0" in nft_path:
            raise ValueError("nft_path must name one executable")
        self.command_name = nft_path
        self._runner = runner

    def run(self, argv: list[str], input_text: str | None) -> None:
        self._runner(argv, input_text)

    def read(self, argv: list[str]) -> str:
        return self._runner(argv, None)


class LibNftablesError(RuntimeError):
    """An in-process libnftables request failed."""

    def __init__(self, operation: str, return_code: int, stderr: str) -> None:
        self.operation = operation
        self.return_code = return_code
        self.stderr = stderr
        detail = stderr.strip() or "libnftables returned no diagnostic"
        super().__init__(f"libnftables {operation} failed ({return_code}): {detail}")


class LibNftablesTransport:
    """In-process libnftables transport; no firewall child process is started."""

    backend_id = "nft-lib"
    command_name = "libnftables"

    def __init__(
        self,
        library_path: str | None = None,
        *,
        finder: Callable[[str], str | None] = ctypes.util.find_library,
        loader: Callable[[str], object] = ctypes.CDLL,
    ) -> None:
        if library_path is not None and (
            not isinstance(library_path, str)
            or not library_path
            or "\0" in library_path
        ):
            raise ValueError("library_path must name one shared library")
        self._library_path = library_path
        self._finder = finder
        self._loader = loader
        self._library: object | None = None
        self._lock = threading.Lock()

    @property
    def library_path(self) -> str:
        path = self._library_path or self._finder("nftables")
        if not path:
            raise FileNotFoundError(
                "libnftables shared library was not found; install libnftables"
            )
        return path

    @staticmethod
    def _signature(function: object, argtypes: list[object], restype: object) -> None:
        setattr(function, "argtypes", argtypes)
        setattr(function, "restype", restype)

    def _load(self) -> object:
        if self._library is not None:
            return self._library
        library = self._loader(self.library_path)
        required = (
            "nft_ctx_new",
            "nft_ctx_free",
            "nft_ctx_buffer_output",
            "nft_ctx_buffer_error",
            "nft_ctx_get_output_buffer",
            "nft_ctx_get_error_buffer",
            "nft_ctx_set_dry_run",
            "nft_run_cmd_from_buffer",
        )
        missing = [name for name in required if not hasattr(library, name)]
        if missing:
            raise RuntimeError(
                "libnftables is missing required symbols: " + ", ".join(missing)
            )
        self._signature(
            library.nft_ctx_new,
            [ctypes.c_uint32],
            ctypes.c_void_p,
        )
        self._signature(library.nft_ctx_free, [ctypes.c_void_p], None)
        self._signature(
            library.nft_ctx_buffer_output,
            [ctypes.c_void_p],
            ctypes.c_int,
        )
        self._signature(
            library.nft_ctx_buffer_error,
            [ctypes.c_void_p],
            ctypes.c_int,
        )
        self._signature(
            library.nft_ctx_get_output_buffer,
            [ctypes.c_void_p],
            ctypes.c_char_p,
        )
        self._signature(
            library.nft_ctx_get_error_buffer,
            [ctypes.c_void_p],
            ctypes.c_char_p,
        )
        self._signature(
            library.nft_ctx_set_dry_run,
            [ctypes.c_void_p, ctypes.c_bool],
            None,
        )
        self._signature(
            library.nft_run_cmd_from_buffer,
            [ctypes.c_void_p, ctypes.c_char_p],
            ctypes.c_int,
        )
        if hasattr(library, "nft_ctx_output_set_json"):
            self._signature(
                library.nft_ctx_output_set_json,
                [ctypes.c_void_p, ctypes.c_bool],
                None,
            )
        elif hasattr(library, "nft_ctx_output_get_flags") and hasattr(
            library,
            "nft_ctx_output_set_flags",
        ):
            self._signature(
                library.nft_ctx_output_get_flags,
                [ctypes.c_void_p],
                ctypes.c_uint,
            )
            self._signature(
                library.nft_ctx_output_set_flags,
                [ctypes.c_void_p, ctypes.c_uint],
                None,
            )
        else:
            raise RuntimeError("libnftables cannot enable JSON output")
        self._library = library
        return library

    @staticmethod
    def _decode(value: bytes | None) -> str:
        return (value or b"").decode("utf-8", errors="replace")

    def _invoke(
        self,
        command: str,
        *,
        operation: str,
        dry_run: bool = False,
        json_output: bool = False,
    ) -> str:
        if not isinstance(command, str) or not command or "\0" in command:
            raise ValueError("libnftables command buffer is invalid")
        with self._lock:
            library = self._load()
            context = library.nft_ctx_new(0)
            if not context:
                raise RuntimeError("libnftables could not allocate a context")
            try:
                if library.nft_ctx_buffer_output(context) != 0:
                    raise RuntimeError("libnftables could not buffer output")
                if library.nft_ctx_buffer_error(context) != 0:
                    raise RuntimeError("libnftables could not buffer errors")
                library.nft_ctx_set_dry_run(context, dry_run)
                if json_output:
                    if hasattr(library, "nft_ctx_output_set_json"):
                        library.nft_ctx_output_set_json(context, True)
                    else:
                        flags = library.nft_ctx_output_get_flags(context)
                        library.nft_ctx_output_set_flags(
                            context,
                            flags | NFT_CTX_OUTPUT_JSON,
                        )
                return_code = library.nft_run_cmd_from_buffer(
                    context,
                    command.encode("utf-8"),
                )
                stdout = self._decode(library.nft_ctx_get_output_buffer(context))
                stderr = self._decode(library.nft_ctx_get_error_buffer(context))
            finally:
                library.nft_ctx_free(context)
        if return_code != 0:
            raise LibNftablesError(operation, return_code, stderr)
        return stdout

    def run(self, argv: list[str], input_text: str | None) -> None:
        if argv == [self.command_name, "--file", "-"] and input_text is not None:
            self._invoke(input_text, operation="apply")
            return
        if argv == [
            self.command_name,
            "--check",
            "--file",
            "-",
        ] and input_text is not None:
            self._invoke(input_text, operation="dry-run", dry_run=True)
            return
        if (
            len(argv) == 5
            and argv[:4] == [self.command_name, "delete", "table", "ip"]
            and input_text is None
        ):
            table_name = _validate_nft_table_name(argv[4])
            self._invoke(
                f"delete table ip {table_name}\n",
                operation="delete",
            )
            return
        raise ValueError(f"unsupported libnftables runner invocation: {argv!r}")

    def read(self, argv: list[str]) -> str:
        expected = [self.command_name, "--json", "list", "ruleset", "ip"]
        if argv != expected:
            raise ValueError(f"unsupported libnftables read invocation: {argv!r}")
        return self._invoke(
            "list ruleset ip\n",
            operation="list-ruleset",
            json_output=True,
        )


class NftFirewallBackend:
    """Common nft policy rendered through either supported transport."""

    def __init__(self, transport: NftTransport) -> None:
        if transport.backend_id not in {"nft-lib", "nft-exec"}:
            raise ValueError("nft transport has an unsupported backend identifier")
        self.transport = transport
        self.backend_id = transport.backend_id

    def inspect_ownership(self) -> NftOwnershipReport:
        return inspect_nft_ownership(
            nft_path=self.transport.command_name,
            runner=self.transport.read,
        )

    def check_compatibility(self, config: NftDnatConfig) -> None:
        check_nft_dnat_compatibility(
            config,
            ownership=current_nft_ownership("tcpcc-probe"),
            nft_path=self.transport.command_name,
            runner=self.transport.run,
        )

    def install(
        self,
        config: NftDnatConfig,
        ownership: NftOwnership,
    ) -> NftDnatLease:
        return install_nft_dnat(
            config,
            nft_path=self.transport.command_name,
            runner=self.transport.run,
            ownership=ownership,
            backend_id=self.backend_id,
        )


def _new_iptables_chain_name() -> str:
    return f"{IPTABLES_CHAIN_PREFIX}{secrets.token_hex(6)}"


def _validate_iptables_chain_name(name: str) -> str:
    if not isinstance(name, str) or IPTABLES_CHAIN_NAME.fullmatch(name) is None:
        raise ValueError(
            "iptables chain name must contain 1-28 ASCII letters, digits, "
            "underscores, or hyphens and start with a letter"
        )
    return name


def _iptables_rules(
    config: NftDnatConfig,
    chain_name: str,
    ownership: NftOwnership,
) -> tuple[list[str], list[str]]:
    exact = [
        "-d",
        f"{config.listen_address}/32",
        "-p",
        "tcp",
        "-m",
        "tcp",
        "--dport",
        str(config.listen_port),
    ]
    jump = [
        *exact,
        "-m",
        "comment",
        "--comment",
        f"tcpcc.jump.v1 chain={chain_name}",
        "-j",
        chain_name,
    ]
    dnat = [
        *exact,
        "-m",
        "comment",
        "--comment",
        ownership.marker(),
        "-j",
        "DNAT",
        "--to-destination",
        f"{config.target_address}:{config.target_port}",
    ]
    return jump, dnat


def _iptables_restore_line(chain: str, arguments: list[str]) -> str:
    rendered: list[str] = ["-A", chain]
    for argument in arguments:
        if any(character.isspace() for character in argument):
            if any(character in argument for character in ('"', "\r", "\n")):
                raise ValueError("iptables argument cannot be quoted safely")
            rendered.append(f'"{argument}"')
        else:
            rendered.append(argument)
    return " ".join(rendered)


def _iptables_restore_batch(
    config: NftDnatConfig,
    chain_name: str,
    ownership: NftOwnership,
    *,
    declare_chain: bool,
) -> str:
    jump, dnat = _iptables_rules(config, chain_name, ownership)
    lines = ["*nat"]
    if declare_chain:
        lines.append(f":{chain_name} - [0:0]")
    lines.extend(
        (
            _iptables_restore_line(chain_name, dnat),
            _iptables_restore_line("PREROUTING", jump),
            "COMMIT",
        )
    )
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class IptablesOwnershipObservation:
    """Classification of one tcpcc-owned iptables user chain."""

    chain_name: str
    status: str
    owner_pid: int | None
    owner_start_time: int | None
    tun_name: str | None
    detail: str
    remediation: str

    @property
    def table_name(self) -> str:
        """Compatibility accessor used by the composed lifecycle diagnostic."""

        return self.chain_name

    def as_dict(self) -> dict[str, object]:
        return {
            "chain": self.chain_name,
            "status": self.status,
            "owner_pid": self.owner_pid,
            "owner_start_time": self.owner_start_time,
            "tun": self.tun_name,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class IptablesOwnershipReport:
    """Stable read-only ownership report for the legacy-compatible backend."""

    observations: tuple[IptablesOwnershipObservation, ...]

    @property
    def blocking(self) -> bool:
        return any(item.status != "active" for item in self.observations)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "tcpcc.iptables-ownership.v1",
            "backend": "iptables",
            "blocking": self.blocking,
            "chains": [item.as_dict() for item in self.observations],
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))


class IptablesInstallRollbackError(RuntimeError):
    """iptables installation failed and its private-chain rollback also failed."""

    def __init__(
        self,
        install_error: BaseException,
        cleanup_errors: tuple[BaseException, ...],
    ) -> None:
        self.install_error = install_error
        self.cleanup_errors = cleanup_errors
        details = "; ".join(
            f"{type(error).__name__}: {error}" for error in cleanup_errors
        )
        super().__init__(
            f"iptables install failed ({install_error}) and private-chain "
            f"rollback failed ({details})"
        )


class IptablesDnatLease:
    """Own one exact PREROUTING jump and its private iptables user chain."""

    backend_id = "iptables"

    def __init__(
        self,
        chain_name: str,
        jump_arguments: list[str],
        *,
        iptables_path: str,
        runner: FirewallCommandRunner,
    ) -> None:
        self.chain_name = _validate_iptables_chain_name(chain_name)
        self._jump_arguments = list(jump_arguments)
        self._iptables_path = iptables_path
        self._runner = runner
        self._closed = False

    @property
    def resource_name(self) -> str:
        return self.chain_name

    @property
    def table_name(self) -> str:
        """Compatibility accessor while the CLI still exposes table_name."""

        return self.chain_name

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        commands = (
            [
                self._iptables_path,
                "--wait",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                *self._jump_arguments,
            ],
            [
                self._iptables_path,
                "--wait",
                "-t",
                "nat",
                "-F",
                self.chain_name,
            ],
            [
                self._iptables_path,
                "--wait",
                "-t",
                "nat",
                "-X",
                self.chain_name,
            ],
        )
        failures: list[CleanupFailure] = []
        labels = ("jump", "flush", "delete-chain")
        for label, command in zip(labels, commands, strict=True):
            try:
                self._runner(command, None)
            except BaseException as error:
                failures.append(
                    CleanupFailure(f"iptables:{self.chain_name}:{label}", error)
                )
        if failures:
            raise CleanupError(tuple(failures))


class IptablesFirewallBackend:
    """iptables compatibility path with a private chain and exact shared jump."""

    backend_id = "iptables"

    def __init__(
        self,
        *,
        iptables_path: str = "iptables",
        restore_path: str = "iptables-restore",
        save_path: str = "iptables-save",
        runner: FirewallCommandRunner = _run_firewall_command,
        chain_name_factory: NameFactory = _new_iptables_chain_name,
        proc_root: Path = Path("/proc"),
        reader: Reader = _read_text,
    ) -> None:
        for path, field in (
            (iptables_path, "iptables_path"),
            (restore_path, "restore_path"),
            (save_path, "save_path"),
        ):
            if not isinstance(path, str) or not path or "\0" in path:
                raise ValueError(f"{field} must name one executable")
        self.iptables_path = iptables_path
        self.restore_path = restore_path
        self.save_path = save_path
        self._runner = runner
        self._chain_name_factory = chain_name_factory
        self._proc_root = proc_root
        self._reader = reader

    def _remediation(self, chain_name: str) -> str:
        return (
            f"inspect with: {self.iptables_path} -t nat -S PREROUTING and "
            f"{self.iptables_path} -t nat -S {chain_name}; after verifying "
            "ownership, delete the exact tcpcc.jump.v1 rule shown after "
            f"-A PREROUTING with: {self.iptables_path} -t nat -D PREROUTING "
            f"<rule arguments>; then run: {self.iptables_path} -t nat -F "
            f"{chain_name}; then run: {self.iptables_path} -t nat -X "
            f"{chain_name}"
        )

    def _classify(
        self,
        chain_name: str,
        comment: str,
    ) -> IptablesOwnershipObservation:
        match = NFT_OWNER_MARKER.fullmatch(comment)
        if (
            IPTABLES_CHAIN_NAME.fullmatch(chain_name) is None
            or match is None
        ):
            safe_chain = (
                chain_name
                if IPTABLES_CHAIN_NAME.fullmatch(chain_name) is not None
                else "malformed"
            )
            remediation = "inspect the complete iptables nat table manually"
            if safe_chain != "malformed":
                remediation = self._remediation(safe_chain)
            return IptablesOwnershipObservation(
                chain_name=safe_chain,
                status="malformed",
                owner_pid=None,
                owner_start_time=None,
                tun_name=None,
                detail="unsupported or malformed tcpcc ownership marker",
                remediation=remediation,
            )

        pid = int(match.group(1))
        expected_start = int(match.group(2))
        tun_name = match.group(3)
        status = "stale"
        detail = "owner process is absent"
        try:
            actual_start = _process_start_time(
                pid,
                proc_root=self._proc_root,
                reader=self._reader,
            )
        except FileNotFoundError:
            pass
        except (OSError, UnicodeError, ValueError):
            detail = "owner process identity is unreadable"
        else:
            if actual_start == expected_start:
                status = "active"
                detail = "owner pid and process start time match"
            else:
                detail = "owner pid was reused by a different process"
        return IptablesOwnershipObservation(
            chain_name=chain_name,
            status=status,
            owner_pid=pid,
            owner_start_time=expected_start,
            tun_name=tun_name,
            detail=detail,
            remediation="" if status == "active" else self._remediation(chain_name),
        )

    def inspect_ownership(self) -> IptablesOwnershipReport:
        raw = self._runner([self.save_path, "-t", "nat"], None)
        reserved_chains: set[str] = set()
        markers: dict[str, list[str]] = {}
        for line in raw.splitlines():
            if line.startswith(":"):
                chain_name = line[1:].split(None, 1)[0]
                if IPTABLES_OWNED_CHAIN.fullmatch(chain_name) is not None:
                    reserved_chains.add(chain_name)
                continue
            if not line.startswith("-A "):
                continue
            try:
                tokens = shlex.split(line)
            except ValueError:
                continue
            if len(tokens) < 2 or tokens[0] != "-A":
                continue
            try:
                comment_index = tokens.index("--comment")
                comment = tokens[comment_index + 1]
            except (ValueError, IndexError):
                continue
            if not comment.startswith(NFT_OWNER_PREFIX):
                continue
            markers.setdefault(tokens[1], []).append(comment)

        observations: list[IptablesOwnershipObservation] = []
        for chain_name in sorted(reserved_chains | set(markers)):
            owned_markers = markers.get(chain_name, [])
            if len(owned_markers) != 1:
                detail = (
                    "reserved tcpcc chain has no ownership marker"
                    if not owned_markers
                    else "tcpcc chain has multiple ownership markers"
                )
                observations.append(
                    IptablesOwnershipObservation(
                        chain_name=chain_name,
                        status="malformed",
                        owner_pid=None,
                        owner_start_time=None,
                        tun_name=None,
                        detail=detail,
                        remediation=self._remediation(chain_name),
                    )
                )
                continue
            observations.append(self._classify(chain_name, owned_markers[0]))
        return IptablesOwnershipReport(tuple(observations))

    def check_compatibility(self, config: NftDnatConfig) -> None:
        if not isinstance(config, NftDnatConfig):
            raise TypeError("config must be an NftDnatConfig")
        chain_name = _validate_iptables_chain_name(self._chain_name_factory())
        ownership = current_nft_ownership("tcpcc-probe")
        self._runner(
            [self.restore_path, "--wait", "--test", "--noflush"],
            _iptables_restore_batch(
                config,
                chain_name,
                ownership,
                declare_chain=True,
            ),
        )

    def install(
        self,
        config: NftDnatConfig,
        ownership: NftOwnership,
    ) -> IptablesDnatLease:
        if not isinstance(config, NftDnatConfig):
            raise TypeError("config must be an NftDnatConfig")
        if not isinstance(ownership, NftOwnership):
            raise TypeError("ownership must be an NftOwnership")
        chain_name = _validate_iptables_chain_name(
            self._chain_name_factory()
            if config.table_name is None
            else config.table_name
        )
        jump, _dnat = _iptables_rules(config, chain_name, ownership)
        self._runner(
            [
                self.iptables_path,
                "--wait",
                "-t",
                "nat",
                "-N",
                chain_name,
            ],
            None,
        )
        try:
            self._runner(
                [self.restore_path, "--wait", "--noflush"],
                _iptables_restore_batch(
                    config,
                    chain_name,
                    ownership,
                    declare_chain=False,
                ),
            )
        except BaseException as install_error:
            cleanup_errors: list[BaseException] = []
            for action in ("-F", "-X"):
                try:
                    self._runner(
                        [
                            self.iptables_path,
                            "--wait",
                            "-t",
                            "nat",
                            action,
                            chain_name,
                        ],
                        None,
                    )
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            if cleanup_errors:
                raise IptablesInstallRollbackError(
                    install_error,
                    tuple(cleanup_errors),
                ) from install_error
            raise
        return IptablesDnatLease(
            chain_name,
            jump,
            iptables_path=self.iptables_path,
            runner=self._runner,
        )


def create_firewall_backend(
    backend_id: str,
    *,
    nft_path: str = "nft",
    iptables_path: str = "iptables",
    iptables_restore_path: str = "iptables-restore",
    iptables_save_path: str = "iptables-save",
) -> FirewallBackend:
    """Construct one explicit backend; automatic fallback is a later CLI policy."""

    if backend_id == "nft-lib":
        return NftFirewallBackend(LibNftablesTransport())
    if backend_id == "nft-exec":
        return NftFirewallBackend(NftExecTransport(nft_path))
    if backend_id == "iptables":
        return IptablesFirewallBackend(
            iptables_path=iptables_path,
            restore_path=iptables_restore_path,
            save_path=iptables_save_path,
        )
    raise ValueError(
        "firewall backend must be one of: " + ", ".join(sorted(FIREWALL_BACKENDS))
    )


@dataclass(frozen=True)
class HostNetworkConfig:
    """Validated inputs for one complete server-ingress host transaction."""

    requested_cc: str
    tun: TunConfig
    dnat: NftDnatConfig
    firewall_backend: str = "nft-exec"

    def __post_init__(self) -> None:
        if not isinstance(self.requested_cc, str) or CC_NAME.fullmatch(
            self.requested_cc
        ) is None:
            raise ValueError("requested_cc is not a supported algorithm name")
        if not isinstance(self.tun, TunConfig):
            raise TypeError("tun must be a TunConfig")
        if not isinstance(self.dnat, NftDnatConfig):
            raise TypeError("dnat must be an NftDnatConfig")
        if self.firewall_backend not in FIREWALL_BACKENDS:
            raise ValueError(
                "firewall_backend must be one of: "
                + ", ".join(sorted(FIREWALL_BACKENDS))
            )
        if self.dnat.target_address != self.tun.guest_address:
            raise ValueError("DNAT target address must equal the TUN guest address")


class HostPreflightError(RuntimeError):
    """Required preflight checks failed before any resource acquisition."""

    def __init__(self, report: PreflightReport) -> None:
        self.report = report
        failed = ", ".join(
            check.check_id for check in report.checks if check.status == "fail"
        )
        super().__init__(f"host preflight failed: {failed}")


class StaleOwnershipError(RuntimeError):
    """Marked stale or malformed tables require explicit operator action."""

    def __init__(
        self,
        report: NftOwnershipReport | IptablesOwnershipReport,
    ) -> None:
        self.report = report
        blocked = ", ".join(
            f"{item.table_name}({item.status})"
            for item in report.observations
            if item.status != "active"
        )
        backend = "iptables" if isinstance(report, IptablesOwnershipReport) else "nft"
        super().__init__(f"unsafe tcpcc {backend} ownership state: {blocked}")


class StartupRollbackError(RuntimeError):
    """Preserve a primary startup error together with every rollback failure."""

    def __init__(
        self,
        startup_error: BaseException,
        cleanup_error: CleanupError,
    ) -> None:
        self.startup_error = startup_error
        self.cleanup_error = cleanup_error
        details = "; ".join(
            f"{failure.label}: {type(failure.error).__name__}: {failure.error}"
            for failure in cleanup_error.failures
        )
        super().__init__(
            f"host-network startup failed ({type(startup_error).__name__}: "
            f"{startup_error}) and rollback failed ({details})"
        )


class HostNetworkLease:
    """The exact TUN and DNAT resources owned by one running instance."""

    def __init__(
        self,
        *,
        preflight: PreflightReport,
        ownership: NftOwnershipReport | IptablesOwnershipReport,
        tun: TunQueue,
        dnat: FirewallDnatLease,
        journal: OwnershipJournal,
    ) -> None:
        self.preflight = preflight
        self.ownership = ownership
        self.tun = tun
        self.dnat = dnat
        self._journal = journal

    @property
    def tun_name(self) -> str:
        return self.tun.name

    @property
    def tun_fd(self) -> int:
        return self.tun.fd

    @property
    def table_name(self) -> str:
        return self.dnat.resource_name

    @property
    def firewall_backend(self) -> str:
        return self.dnat.backend_id

    @property
    def firewall_resource(self) -> str:
        return self.dnat.resource_name

    @property
    def closed(self) -> bool:
        return self._journal.closed

    def close(self) -> None:
        self._journal.close()


def _rollback_unregistered_resource(
    *,
    journal: OwnershipJournal,
    label: str,
    callback: CleanupCallback,
    startup_error: BaseException,
) -> None:
    failures: list[CleanupFailure] = []
    try:
        callback()
    except BaseException as error:
        failures.append(CleanupFailure(label, error))
    try:
        journal.close()
    except CleanupError as error:
        failures.extend(error.failures)
    if failures:
        cleanup_error = CleanupError(tuple(failures))
        raise StartupRollbackError(startup_error, cleanup_error) from startup_error
    raise startup_error


def _register_resource(
    journal: OwnershipJournal,
    label: str,
    callback: CleanupCallback,
) -> None:
    try:
        journal.defer(label, callback)
    except BaseException as error:
        _rollback_unregistered_resource(
            journal=journal,
            label=label,
            callback=callback,
            startup_error=error,
        )


def acquire_host_network(
    config: HostNetworkConfig,
    *,
    host_inspector: HostInspector | None = None,
    nft_path: str = "nft",
    iptables_path: str = "iptables",
    iptables_restore_path: str = "iptables-restore",
    iptables_save_path: str = "iptables-save",
    firewall: FirewallBackend | None = None,
    preflight_collector: Callable[[str], PreflightReport] | None = None,
    ownership_collector: Callable[
        [], NftOwnershipReport | IptablesOwnershipReport
    ] | None = None,
    compatibility_checker: Callable[[NftDnatConfig], None] | None = None,
    tun_acquirer: Callable[[TunConfig], TunQueue] = create_tun_queue,
    dnat_acquirer: Callable[
        [NftDnatConfig, NftOwnership], FirewallDnatLease
    ] | None = None,
    identity_factory: Callable[[str], NftOwnership] = current_nft_ownership,
    journal_factory: Callable[[], OwnershipJournal] = OwnershipJournal,
) -> HostNetworkLease:
    """Acquire preflight, stale scan, TUN, then DNAT as one transaction."""

    if not isinstance(config, HostNetworkConfig):
        raise TypeError("config must be a HostNetworkConfig")
    if preflight_collector is None:
        preflight_collector = lambda cc: collect_preflight(
            cc,
            host_inspector,
            firewall_backend=config.firewall_backend,
            nft_path=nft_path,
            iptables_path=iptables_path,
            iptables_restore_path=iptables_restore_path,
            iptables_save_path=iptables_save_path,
        )
    if (
        ownership_collector is None
        or compatibility_checker is None
        or dnat_acquirer is None
    ):
        if firewall is None:
            firewall = create_firewall_backend(
                config.firewall_backend,
                nft_path=nft_path,
                iptables_path=iptables_path,
                iptables_restore_path=iptables_restore_path,
                iptables_save_path=iptables_save_path,
            )
        if firewall.backend_id != config.firewall_backend:
            raise ValueError(
                "configured firewall backend does not match injected backend"
            )
    if ownership_collector is None:
        ownership_collector = firewall.inspect_ownership
    if compatibility_checker is None:
        compatibility_checker = firewall.check_compatibility
    if dnat_acquirer is None:
        dnat_acquirer = firewall.install

    preflight = preflight_collector(config.requested_cc)
    if not isinstance(preflight, PreflightReport):
        raise TypeError("preflight_collector returned an invalid report")
    if not preflight.ok:
        raise HostPreflightError(preflight)
    ownership = ownership_collector()
    if not isinstance(ownership, (NftOwnershipReport, IptablesOwnershipReport)):
        raise TypeError("ownership_collector returned an invalid report")
    if ownership.blocking:
        raise StaleOwnershipError(ownership)
    compatibility_checker(config.dnat)

    journal = journal_factory()
    if not isinstance(journal, OwnershipJournal):
        raise TypeError("journal_factory returned an invalid journal")
    try:
        tun = tun_acquirer(config.tun)
        _register_resource(journal, f"tun:{tun.name}", tun.close)
        owner = identity_factory(tun.name)
        dnat = dnat_acquirer(config.dnat, owner)
        if not isinstance(dnat.backend_id, str) or not dnat.resource_name:
            raise TypeError("dnat_acquirer returned an invalid firewall lease")
        _register_resource(
            journal,
            f"{dnat.backend_id}:{dnat.resource_name}",
            dnat.close,
        )
    except StartupRollbackError:
        raise
    except BaseException as startup_error:
        try:
            journal.close()
        except CleanupError as cleanup_error:
            raise StartupRollbackError(
                startup_error,
                cleanup_error,
            ) from startup_error
        raise
    return HostNetworkLease(
        preflight=preflight,
        ownership=ownership,
        tun=tun,
        dnat=dnat,
        journal=journal,
    )


class ShutdownSignals:
    """Turn SIGINT/SIGTERM into an orderly, idempotent shutdown request."""

    def __init__(
        self,
        handled: tuple[int, ...] = (signal.SIGINT, signal.SIGTERM),
    ) -> None:
        if not handled or len(set(handled)) != len(handled):
            raise ValueError("handled signals must be a non-empty unique tuple")
        self._handled = handled
        self._event = threading.Event()
        self._requested_signal: int | None = None
        self._previous: dict[int, object] = {}
        self._installed = False

    @property
    def requested(self) -> bool:
        return self._event.is_set()

    @property
    def requested_signal(self) -> int | None:
        return self._requested_signal

    def request(self, signum: int) -> None:
        if self._requested_signal is None:
            self._requested_signal = signum
        self._event.set()

    def _handler(self, signum: int, _frame: object) -> None:
        self.request(signum)

    def __enter__(self) -> ShutdownSignals:
        if self._installed:
            raise RuntimeError("shutdown signal handlers are already installed")
        installed: list[int] = []
        try:
            for signum in self._handled:
                self._previous[signum] = signal.signal(signum, self._handler)
                installed.append(signum)
        except BaseException:
            for signum in reversed(installed):
                signal.signal(signum, self._previous[signum])
            self._previous.clear()
            raise
        self._installed = True
        return self

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    def restore(self) -> None:
        if not self._installed:
            return
        for signum in reversed(self._handled):
            signal.signal(signum, self._previous[signum])
        self._previous.clear()
        self._installed = False

    def __exit__(
        self,
        _exc_type: object,
        _exc_value: object,
        _traceback: object,
    ) -> None:
        self.restore()

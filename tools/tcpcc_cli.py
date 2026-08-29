#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Stable server-ingress CLI and hosted-kernel service orchestration."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, TextIO

from tcpcc_control import (
    OP_ACCEPT_NONBLOCK,
    OP_BIND_IP,
    OP_BRIDGE_CANCEL,
    OP_BRIDGE_JOIN_RESULT,
    OP_BRIDGE_START,
    OP_CLOSE,
    OP_GET_CC,
    OP_L3_ATTACH_IP,
    OP_LISTEN,
    OP_SET_CC,
    OP_SHUTDOWN,
    OP_SOCKET_IP,
    BridgeResult,
    ControlClient,
    ControlOperationError,
    ControlProtocolError,
    ControlResponse,
    decode_bridge_result,
    encode_ip_endpoint,
    encode_l3_config,
)
from tcpcc_host import (
    CC_NAME,
    FIREWALL_BACKENDS,
    HostNetworkConfig,
    HostNetworkLease,
    HostPreflightError,
    NftDnatConfig,
    ShutdownSignals,
    StaleOwnershipError,
    TunConfig,
    acquire_host_network,
)

DEFAULT_TUN_HOST_ADDRESS = "198.18.0.1"
DEFAULT_TUN_GUEST_ADDRESS = "198.18.0.2"
DEFAULT_TUN_HOST_ADDRESS_IPV6 = "fd00:198:18::1"
DEFAULT_TUN_GUEST_ADDRESS_IPV6 = "fd00:198:18::2"
DEFAULT_BACKLOG = 128
DEFAULT_POLL_INTERVAL = 0.01
DEFAULT_KERNEL_SHUTDOWN_TIMEOUT = 10.0
DEFAULT_MEMORY_MIB = 128
MINIMUM_MEMORY_MIB = 128
BRIDGE_SESSION_LIMIT = 1048575
DEFAULT_MAX_CONNECTIONS = 0
DEFAULT_SHUTDOWN_GRACE_PERIOD = 5.0
MAX_SHUTDOWN_GRACE_PERIOD = 300.0
BRIDGE_BUFFER_LIMIT = 16 * 1024
BRIDGE_TOTAL_BUFFER_LIMIT = 256 * 1024
BRIDGE_JOIN_POLL_MS = 1
BRIDGE_DRAIN_JOIN_SLICE_MS = 50
BRIDGE_SHUTDOWN_JOIN_MS = 5000
HOST_EVENT_ERROR = 1 << 3
IPTABLES_VARIANTS = ("iptables", "iptables-nft", "iptables-legacy")
EVENT_SCHEMA = "tcpcc.runtime.v1"

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_EXEC = 2
EM_X86_64 = 62
PT_INTERP = 3


class TcpccServiceError(RuntimeError):
    """Base class for product runtime errors."""


class RuntimeExitedError(TcpccServiceError):
    """The hosted kernel exited before an orderly shutdown."""


class RuntimeCleanupError(TcpccServiceError):
    """One or more hosted-runtime cleanup boundaries failed."""

    def __init__(self, failures: tuple[BaseException, ...]) -> None:
        self.failures = failures
        detail = "; ".join(
            f"{type(error).__name__}: {error}" for error in failures
        )
        super().__init__(f"hosted runtime cleanup failed: {detail}")


class ServiceCleanupError(TcpccServiceError):
    """Preserve a service error together with later cleanup failures."""

    def __init__(
        self,
        primary: BaseException | None,
        cleanup_failures: tuple[BaseException, ...],
    ) -> None:
        self.primary = primary
        self.cleanup_failures = cleanup_failures
        cleanup = "; ".join(
            f"{type(error).__name__}: {error}" for error in cleanup_failures
        )
        if primary is None:
            message = f"service cleanup failed: {cleanup}"
        else:
            message = (
                f"service failed ({type(primary).__name__}: {primary}) and "
                f"cleanup failed ({cleanup})"
            )
        super().__init__(message)


@dataclass(frozen=True)
class Endpoint:
    address: str
    port: int

    @classmethod
    def parse(cls, value: str, field: str) -> Endpoint:
        if not isinstance(value, str) or "\0" in value:
            raise ValueError(f"{field} must use IPv4:port or [IPv6]:port syntax")
        if value.startswith("["):
            closing = value.find("]")
            if closing < 0 or closing + 1 >= len(value) or value[closing + 1] != ":":
                raise ValueError(
                    f"{field} must use IPv4:port or [IPv6]:port syntax"
                )
            address_text = value[1:closing]
            port_text = value[closing + 2 :]
            expected_version = 6
        else:
            if value.count(":") != 1:
                raise ValueError(
                    f"{field} must use IPv4:port or [IPv6]:port syntax"
                )
            address_text, port_text = value.rsplit(":", 1)
            expected_version = 4
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError as error:
            raise ValueError(f"{field} address must be a literal IP address") from error
        if address.version != expected_version:
            raise ValueError(f"{field} has mismatched address syntax")
        if address.is_unspecified or address.is_multicast or (
            address.version == 4 and int(address) == 0xFFFFFFFF
        ):
            raise ValueError(f"{field} address must be a usable unicast IP address")
        if not port_text.isascii() or not port_text.isdecimal():
            raise ValueError(f"{field} port must be from 1 through 65535")
        port = int(port_text, 10)
        if not 1 <= port <= 65535:
            raise ValueError(f"{field} port must be from 1 through 65535")
        return cls(str(address), port)

    @property
    def ipv4_u32(self) -> int:
        return int(ipaddress.IPv4Address(self.address))

    @property
    def version(self) -> int:
        return ipaddress.ip_address(self.address).version

    def __str__(self) -> str:
        if self.version == 6:
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"


@dataclass(frozen=True)
class ServiceConfig:
    listen: Endpoint
    backend: Endpoint
    cc: str
    kernel: Path
    memory_mib: int = DEFAULT_MEMORY_MIB
    firewall_backend: str = "nft-lib"
    iptables_variant: str = "iptables"
    tun_name: str | None = None
    tun_host_address: str | None = None
    tun_guest_address: str | None = None
    backlog: int = DEFAULT_BACKLOG
    max_connections: int = DEFAULT_MAX_CONNECTIONS
    shutdown_grace_period: float = DEFAULT_SHUTDOWN_GRACE_PERIOD
    poll_interval: float = DEFAULT_POLL_INTERVAL

    def __post_init__(self) -> None:
        if not isinstance(self.listen, Endpoint):
            raise TypeError("listen must be an Endpoint")
        if not isinstance(self.backend, Endpoint):
            raise TypeError("backend must be an Endpoint")
        if self.backend.version != 4 or self.backend.address != "127.0.0.1":
            raise ValueError(
                "backend must use 127.0.0.1; the current hosted bridge "
                "intentionally reaches only a local application"
            )
        default_host = (
            DEFAULT_TUN_HOST_ADDRESS
            if self.listen.version == 4
            else DEFAULT_TUN_HOST_ADDRESS_IPV6
        )
        default_guest = (
            DEFAULT_TUN_GUEST_ADDRESS
            if self.listen.version == 4
            else DEFAULT_TUN_GUEST_ADDRESS_IPV6
        )
        host_address = self.tun_host_address or default_host
        guest_address = self.tun_guest_address or default_guest
        try:
            host = ipaddress.ip_address(host_address)
            guest = ipaddress.ip_address(guest_address)
        except ValueError as error:
            raise ValueError("TUN addresses must be literal IP addresses") from error
        if host.version != self.listen.version or guest.version != self.listen.version:
            raise ValueError("TUN and public-listener address families must match")
        if host == guest or host.is_unspecified or guest.is_unspecified or (
            host.is_multicast or guest.is_multicast
        ):
            raise ValueError("TUN addresses must be distinct usable unicast addresses")
        object.__setattr__(self, "tun_host_address", str(host))
        object.__setattr__(self, "tun_guest_address", str(guest))
        if (
            isinstance(self.memory_mib, bool)
            or not isinstance(self.memory_mib, int)
            or self.memory_mib < MINIMUM_MEMORY_MIB
        ):
            raise ValueError(
                f"hosted memory must be at least {MINIMUM_MEMORY_MIB} MiB"
            )
        if not isinstance(self.cc, str) or CC_NAME.fullmatch(self.cc) is None:
            raise ValueError(
                "cc must contain 1-15 lowercase letters, digits, underscores, "
                "or hyphens"
            )
        if self.firewall_backend not in FIREWALL_BACKENDS:
            raise ValueError(
                "firewall backend must be one of: "
                + ", ".join(sorted(FIREWALL_BACKENDS))
            )
        if self.iptables_variant not in IPTABLES_VARIANTS:
            raise ValueError(
                "iptables variant must be one of: " + ", ".join(IPTABLES_VARIANTS)
            )
        if (
            isinstance(self.backlog, bool)
            or not isinstance(self.backlog, int)
            or not 1 <= self.backlog <= 4096
        ):
            raise ValueError("backlog must be from 1 through 4096")
        if (
            isinstance(self.max_connections, bool)
            or not isinstance(self.max_connections, int)
            or not 0 <= self.max_connections <= BRIDGE_SESSION_LIMIT
        ):
            raise ValueError(
                "max connections must be 0 (unlimited) or from 1 through "
                f"{BRIDGE_SESSION_LIMIT}"
            )
        if (
            isinstance(self.shutdown_grace_period, bool)
            or not isinstance(self.shutdown_grace_period, (int, float))
            or not 0 <= self.shutdown_grace_period <= MAX_SHUTDOWN_GRACE_PERIOD
        ):
            raise ValueError(
                "shutdown grace period must be from 0 through "
                f"{MAX_SHUTDOWN_GRACE_PERIOD:g} seconds"
            )
        if (
            isinstance(self.poll_interval, bool)
            or not isinstance(self.poll_interval, (int, float))
            or not 0 < self.poll_interval <= 1
        ):
            raise ValueError("poll interval must be greater than 0 and at most 1 second")


class ControlChannel(Protocol):
    def transact(
        self,
        operation: int,
        handle: int = 0,
        arg0: int = 0,
        arg1: int = 0,
        data: bytes = b"",
        *,
        allowed_statuses: tuple[int, ...] = (0,),
    ) -> ControlResponse: ...


class Process(Protocol):
    stdin: object
    stdout: object
    pid: int

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


class StopRequest(Protocol):
    @property
    def requested(self) -> bool: ...

    @property
    def requested_signal(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> bool: ...


ProcessFactory = Callable[..., Process]
ControlFactory = Callable[[object, object], ControlChannel]
NetworkAcquirer = Callable[..., HostNetworkLease]


class EventEmitter:
    """Emit stable newline-delimited JSON on stdout and prose on stderr."""

    def __init__(
        self,
        *,
        output: TextIO | None = None,
        diagnostics: TextIO | None = None,
    ) -> None:
        self.output = sys.stdout if output is None else output
        self.diagnostics = sys.stderr if diagnostics is None else diagnostics

    def event(self, event: str, **fields: object) -> None:
        document = {"schema": EVENT_SCHEMA, "event": event, **fields}
        print(
            json.dumps(document, sort_keys=True, separators=(",", ":")),
            file=self.output,
            flush=True,
        )

    def diagnostic(self, message: str) -> None:
        print(f"tcpcc: {message}", file=self.diagnostics, flush=True)


def validate_kernel_image(path: Path) -> Path:
    """Validate the hosted x86-64 ET_EXEC image before host mutation."""

    if not isinstance(path, Path):
        raise TypeError("kernel path must be a pathlib.Path")
    try:
        resolved = path.expanduser().resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise ValueError(f"kernel image is unavailable: {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"kernel image is not a regular file: {resolved}")
    if not os.access(resolved, os.X_OK):
        raise ValueError(f"kernel image is not executable: {resolved}")

    try:
        with resolved.open("rb") as stream:
            raw_header = stream.read(ELF_HEADER.size)
            if len(raw_header) != ELF_HEADER.size:
                raise ValueError("kernel image has a truncated ELF header")
            (
                ident,
                image_type,
                machine,
                elf_version,
                entry,
                program_offset,
                _section_offset,
                _flags,
                header_size,
                program_size,
                program_count,
                _section_size,
                _section_count,
                _section_names,
            ) = ELF_HEADER.unpack(raw_header)
            if ident[:4] != b"\x7fELF":
                raise ValueError("kernel image is not ELF")
            if ident[4] != ELFCLASS64 or ident[5] != ELFDATA2LSB:
                raise ValueError("kernel image must be 64-bit little-endian ELF")
            if image_type != ET_EXEC or machine != EM_X86_64 or elf_version != 1:
                raise ValueError("kernel image must be an x86-64 ET_EXEC ELF")
            if header_size != ELF_HEADER.size or not entry:
                raise ValueError("kernel image has an invalid ELF entry header")
            if (
                not program_count
                or program_size < ELF_PROGRAM_HEADER.size
                or program_offset < ELF_HEADER.size
                or program_offset + program_size * program_count > metadata.st_size
            ):
                raise ValueError("kernel image has an invalid program-header table")
            for index in range(program_count):
                stream.seek(program_offset + index * program_size)
                raw_program = stream.read(ELF_PROGRAM_HEADER.size)
                if len(raw_program) != ELF_PROGRAM_HEADER.size:
                    raise ValueError("kernel image has a truncated program header")
                program_type = ELF_PROGRAM_HEADER.unpack(raw_program)[0]
                if program_type == PT_INTERP:
                    raise ValueError(
                        "kernel image unexpectedly requires an ELF interpreter"
                    )
    except OSError as error:
        raise ValueError(f"kernel image cannot be read: {resolved}: {error}") from error
    return resolved


def _endpoint_argument(field: str) -> Callable[[str], Endpoint]:
    def parse(value: str) -> Endpoint:
        try:
            return Endpoint.parse(value, field)
        except ValueError as error:
            raise argparse.ArgumentTypeError(str(error)) from error

    return parse


def _ip_argument(field: str) -> Callable[[str], str]:
    def parse(value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError(
                f"{field} must be a literal IP address"
            ) from error
        if address.is_unspecified or address.is_multicast or (
            address.version == 4 and int(address) == 0xFFFFFFFF
        ):
            raise argparse.ArgumentTypeError(f"{field} must be usable unicast IP")
        return str(address)

    return parse


def build_parser(*, environ: dict[str, str] | None = None) -> argparse.ArgumentParser:
    environment = os.environ if environ is None else environ
    project_root = Path(__file__).resolve().parents[1]
    repository_kernel = project_root / ".build" / "tcpcc-bootstrap-out" / "vmlinux"
    executable_prefix = Path(sys.argv[0]).resolve().parent.parent
    installed_kernel = executable_prefix / "libexec" / "tcpcc" / "vmlinux"
    fallback_kernel = (
        repository_kernel if repository_kernel.exists() else installed_kernel
    )
    default_kernel = environment.get("TCPCC_KERNEL", str(fallback_kernel))
    parser = argparse.ArgumentParser(
        prog="tcpcc",
        description=(
            "Terminate public TCP inside the hosted Linux stack and bridge it "
            "to one local backend."
        ),
    )
    parser.add_argument(
        "--listen",
        required=True,
        type=_endpoint_argument("listen"),
        metavar="IP:PORT",
        help="exact public IPv4:port or [IPv6]:port TCP endpoint",
    )
    parser.add_argument(
        "--backend",
        required=True,
        type=_endpoint_argument("backend"),
        metavar="127.0.0.1:PORT",
        help="local application endpoint",
    )
    parser.add_argument(
        "--cc",
        required=True,
        help="public-listener TCP congestion-control algorithm",
    )
    parser.add_argument(
        "--kernel",
        type=Path,
        default=Path(default_kernel),
        metavar="PATH",
        help="ARCH=tcpcc vmlinux executable (or set TCPCC_KERNEL)",
    )
    parser.add_argument(
        "--memory-mib",
        type=int,
        default=DEFAULT_MEMORY_MIB,
        metavar="MIB",
        help=(
            "host-backed RAM available to vmlinux "
            f"(default: {DEFAULT_MEMORY_MIB} MiB; minimum: "
            f"{MINIMUM_MEMORY_MIB} MiB)"
        ),
    )
    parser.add_argument(
        "--firewall-backend",
        choices=sorted(FIREWALL_BACKENDS),
        default="nft-lib",
        help="explicit packet-steering implementation; failures never fall back",
    )
    parser.add_argument(
        "--iptables-variant",
        choices=IPTABLES_VARIANTS,
        default="iptables",
        help="xtables frontend used when --firewall-backend=iptables",
    )
    parser.add_argument(
        "--tun-name",
        metavar="NAME",
        help="exclusive nonpersistent TUN name (generated when omitted)",
    )
    parser.add_argument(
        "--tun-host-address",
        type=_ip_argument("tun host address"),
        metavar="IP",
        help="host-side point-to-point address (family-specific default)",
    )
    parser.add_argument(
        "--tun-guest-address",
        type=_ip_argument("tun guest address"),
        metavar="IP",
        help="hosted-stack point-to-point address (family-specific default)",
    )
    parser.add_argument(
        "--backlog",
        type=int,
        default=DEFAULT_BACKLOG,
        metavar="N",
        help="hosted listener backlog (default: 128)",
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=DEFAULT_MAX_CONNECTIONS,
        metavar="N",
        help=(
            "optional simultaneous-connection admission limit; 0 disables "
            f"the policy limit (default: 0; hosted encoding limit: "
            f"{BRIDGE_SESSION_LIMIT})"
        ),
    )
    parser.add_argument(
        "--shutdown-grace-period",
        type=float,
        default=DEFAULT_SHUTDOWN_GRACE_PERIOD,
        metavar="SECONDS",
        help=(
            "time to drain active connections before cancellation "
            f"(default: {DEFAULT_SHUTDOWN_GRACE_PERIOD:g})"
        ),
    )
    return parser


def config_from_namespace(namespace: argparse.Namespace) -> ServiceConfig:
    if namespace.firewall_backend != "iptables" and (
        namespace.iptables_variant != "iptables"
    ):
        raise ValueError(
            "--iptables-variant is valid only with --firewall-backend=iptables"
        )
    if (
        namespace.tun_host_address is not None
        and namespace.tun_host_address == namespace.tun_guest_address
    ):
        raise ValueError("TUN host and guest addresses must be different")
    kernel = validate_kernel_image(namespace.kernel)
    return ServiceConfig(
        listen=namespace.listen,
        backend=namespace.backend,
        cc=namespace.cc,
        kernel=kernel,
        memory_mib=namespace.memory_mib,
        firewall_backend=namespace.firewall_backend,
        iptables_variant=namespace.iptables_variant,
        tun_name=namespace.tun_name,
        tun_host_address=namespace.tun_host_address,
        tun_guest_address=namespace.tun_guest_address,
        backlog=namespace.backlog,
        max_connections=namespace.max_connections,
        shutdown_grace_period=namespace.shutdown_grace_period,
    )


def host_network_config(config: ServiceConfig) -> HostNetworkConfig:
    return HostNetworkConfig(
        requested_cc=config.cc,
        tun=TunConfig(
            host_address=config.tun_host_address,
            guest_address=config.tun_guest_address,
            name=config.tun_name,
        ),
        dnat=NftDnatConfig(
            listen_address=config.listen.address,
            listen_port=config.listen.port,
            target_address=config.tun_guest_address,
            target_port=config.listen.port,
        ),
        firewall_backend=config.firewall_backend,
    )


def iptables_paths(variant: str, ip_version: int) -> tuple[str, str, str]:
    if variant not in IPTABLES_VARIANTS:
        raise ValueError("unsupported iptables variant")
    if ip_version not in {4, 6}:
        raise ValueError("unsupported IP version")
    command = variant if ip_version == 4 else variant.replace("iptables", "ip6tables", 1)
    return command, f"{command}-restore", f"{command}-save"


class HostedKernelRuntime:
    """Own the child process, hosted listener, and active bridge handles."""

    def __init__(
        self,
        config: ServiceConfig,
        *,
        emitter: EventEmitter,
        process_factory: ProcessFactory = subprocess.Popen,
        control_factory: ControlFactory = ControlClient,
        shutdown_timeout: float = DEFAULT_KERNEL_SHUTDOWN_TIMEOUT,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self.emitter = emitter
        self.process_factory = process_factory
        self.control_factory = control_factory
        self.shutdown_timeout = shutdown_timeout
        self.clock = clock
        self.process: Process | None = None
        self.control: ControlChannel | None = None
        self.ifindex: int | None = None
        self.listener_handle: int | None = None
        self.active_bridges: set[int] = set()
        self._l3_attached = False
        self._closed = False

    @property
    def pid(self) -> int:
        if self.process is None:
            raise RuntimeError("hosted process has not started")
        return self.process.pid

    def _channel(self) -> ControlChannel:
        if self.control is None:
            raise RuntimeError("hosted control channel has not started")
        return self.control

    def start(self, tun_fd: int) -> None:
        if self.process is not None:
            raise RuntimeError("hosted runtime is already started")
        if isinstance(tun_fd, bool) or not isinstance(tun_fd, int) or tun_fd < 3:
            raise ValueError("TUN fd must be an inherited descriptor of at least 3")
        self.process = self.process_factory(
            [
                str(self.config.kernel),
                f"--memory-mib={self.config.memory_mib}",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            pass_fds=(tun_fd,),
            close_fds=True,
            bufsize=0,
            start_new_session=True,
        )
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("hosted process did not expose control pipes")
        self.control = self.control_factory(self.process.stdin, self.process.stdout)

        guest_address = self.config.tun_guest_address
        if guest_address is None:
            raise RuntimeError("hosted TUN address was not resolved")
        guest_ip = ipaddress.ip_address(guest_address)
        response = self._channel().transact(
            OP_L3_ATTACH_IP,
            tun_fd,
            data=encode_l3_config(guest_address, guest_ip.max_prefixlen),
        )
        if response.handle <= 0:
            raise ControlProtocolError(
                f"hosted L3 attach returned invalid ifindex {response.handle}"
            )
        self.ifindex = response.handle
        self._l3_attached = True

        response = self._channel().transact(
            OP_SOCKET_IP,
            arg0=self.config.listen.version,
        )
        if response.handle <= 0:
            raise ControlProtocolError(
                f"hosted socket returned invalid handle {response.handle}"
            )
        self.listener_handle = response.handle
        self._channel().transact(
            OP_SET_CC,
            self.listener_handle,
            data=self.config.cc.encode("ascii"),
        )
        self._verify_cc(self.listener_handle, "listener")
        self._channel().transact(
            OP_BIND_IP,
            self.listener_handle,
            data=encode_ip_endpoint(guest_address, self.config.listen.port),
        )
        self._channel().transact(
            OP_LISTEN,
            self.listener_handle,
            self.config.backlog,
        )

    def _verify_cc(self, handle: int, label: str) -> None:
        response = self._channel().transact(OP_GET_CC, handle)
        try:
            observed = response.data.decode("ascii")
        except UnicodeDecodeError as error:
            raise ControlProtocolError(
                f"hosted {label} returned a non-ASCII congestion-control name"
            ) from error
        if observed != self.config.cc:
            raise ControlProtocolError(
                f"hosted {label} congestion control is {observed!r}, "
                f"expected {self.config.cc!r}"
            )

    def _ensure_running(self) -> None:
        if self.process is None:
            raise RuntimeError("hosted process has not started")
        status = self.process.poll()
        if status is not None:
            raise RuntimeExitedError(
                f"hosted kernel exited unexpectedly with status {status}"
            )

    def _join_bridge_result(self, handle: int, timeout_ms: int) -> bool:
        try:
            response = self._channel().transact(
                OP_BRIDGE_JOIN_RESULT,
                handle,
                timeout_ms,
            )
        except ControlOperationError as error:
            if error.status == -errno.ETIMEDOUT:
                return False
            self.active_bridges.discard(handle)
            self.emitter.event(
                "connection-closed",
                bridge_handle=handle,
                status=error.status,
                active_connections=len(self.active_bridges),
                max_connections=self.config.max_connections,
            )
            self.emitter.diagnostic(
                f"bridge {handle} could not return its terminal result: "
                f"hosted status {error.status}"
            )
            return True

        result = decode_bridge_result(
            response.data,
            allow_terminal_error=True,
        )
        self._validate_bridge_contract(result)
        self.active_bridges.discard(handle)
        self.emitter.event(
            "connection-closed",
            bridge_handle=handle,
            status=result.status,
            active_connections=len(self.active_bridges),
            max_connections=self.config.max_connections,
            public_to_backend_bytes=result.public_to_backend_bytes,
            backend_to_public_bytes=result.backend_to_public_bytes,
            terminal_events=result.terminal_events,
            host_send_eagain=result.host_send_eagain,
            host_partial_writes=result.host_partial_writes,
            host_recv_eagain=result.host_recv_eagain,
        )
        if result.status:
            self.emitter.diagnostic(
                f"bridge {handle} closed with hosted status {result.status}"
            )
        return True

    def _reap_bridges(self) -> None:
        for handle in tuple(self.active_bridges):
            self._join_bridge_result(handle, BRIDGE_JOIN_POLL_MS)

    @staticmethod
    def _validate_bridge_contract(result: BridgeResult) -> None:
        if result.session_limit != BRIDGE_SESSION_LIMIT:
            raise ControlProtocolError(
                f"hosted bridge session limit is {result.session_limit}, "
                f"expected {BRIDGE_SESSION_LIMIT}"
            )
        if (
            result.buffer_limit != BRIDGE_BUFFER_LIMIT
            or result.total_buffer_limit != BRIDGE_TOTAL_BUFFER_LIMIT
        ):
            raise ControlProtocolError("hosted bridge buffer contract changed")
        if not result.status and result.terminal_events & HOST_EVENT_ERROR:
            raise ControlProtocolError(
                "successful hosted bridge result contains a host error event"
            )

    def _accept_available(self) -> None:
        if self.listener_handle is None:
            raise RuntimeError("hosted listener is unavailable")
        while (
            not self.config.max_connections
            or len(self.active_bridges) < self.config.max_connections
        ):
            try:
                accepted = self._channel().transact(
                    OP_ACCEPT_NONBLOCK,
                    self.listener_handle,
                ).handle
            except ControlOperationError as error:
                if error.status in {-errno.EAGAIN, -errno.EWOULDBLOCK}:
                    return
                raise
            if accepted <= 0:
                raise ControlProtocolError(
                    f"hosted accept returned invalid handle {accepted}"
                )
            transferred = False
            try:
                self._verify_cc(accepted, "accepted socket")
                try:
                    response = self._channel().transact(
                        OP_BRIDGE_START,
                        accepted,
                        self.config.backend.ipv4_u32,
                        self.config.backend.port,
                    )
                except ControlOperationError as error:
                    self.emitter.event(
                        "connection-rejected",
                        status=error.status,
                        backend=str(self.config.backend),
                    )
                    self.emitter.diagnostic(
                        "could not connect an accepted flow to backend "
                        f"{self.config.backend}: hosted status {error.status}"
                    )
                    continue
                if response.handle <= 0:
                    raise ControlProtocolError(
                        f"bridge start returned invalid handle {response.handle}"
                    )
                self.active_bridges.add(response.handle)
                transferred = True
                self.emitter.event(
                    "connection-opened",
                    bridge_handle=response.handle,
                    accepted_cc=self.config.cc,
                    backend=str(self.config.backend),
                    active_connections=len(self.active_bridges),
                    max_connections=self.config.max_connections,
                )
            finally:
                if not transferred:
                    try:
                        self._channel().transact(
                            OP_CLOSE,
                            accepted,
                            allowed_statuses=(0, -errno.EBADF),
                        )
                    except BaseException as error:
                        self.emitter.diagnostic(
                            f"accepted socket {accepted} cleanup failed: {error}"
                        )

    def poll_once(self) -> None:
        self._ensure_running()
        self._reap_bridges()
        self._accept_available()

    def serve(self, stop: StopRequest) -> None:
        while not stop.requested:
            self.poll_once()
            stop.wait(self.config.poll_interval)

    @staticmethod
    def _close_pipe(pipe: object) -> None:
        close = getattr(pipe, "close", None)
        if close is not None:
            close()

    def _force_stop(self) -> None:
        if self.process is None or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2.0)

    def _drain_bridges(self) -> None:
        if not self.active_bridges:
            return

        grace_period = float(self.config.shutdown_grace_period)
        self.emitter.event(
            "draining",
            active_connections=len(self.active_bridges),
            grace_period=grace_period,
        )
        if grace_period <= 0:
            return

        deadline = self.clock() + grace_period
        while self.active_bridges:
            for handle in tuple(self.active_bridges):
                remaining = deadline - self.clock()
                if remaining <= 0:
                    break
                timeout_ms = max(
                    1,
                    min(
                        BRIDGE_DRAIN_JOIN_SLICE_MS,
                        int(remaining * 1000),
                    ),
                )
                self._join_bridge_result(handle, timeout_ms)
            if self.clock() >= deadline:
                break

        if self.active_bridges:
            self.emitter.event(
                "drain-timeout",
                remaining_connections=len(self.active_bridges),
                grace_period=grace_period,
            )
            self.emitter.diagnostic(
                f"shutdown grace period expired with "
                f"{len(self.active_bridges)} active connection(s)"
            )

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.process is None:
            return

        failures: list[BaseException] = []
        process_was_running = self.process.poll() is None
        try:
            if process_was_running and self.control is not None and self._l3_attached:
                if self.listener_handle is not None:
                    listener = self.listener_handle
                    self.listener_handle = None
                    try:
                        self._channel().transact(
                            OP_CLOSE,
                            listener,
                            allowed_statuses=(0, -errno.EBADF),
                        )
                    except BaseException as error:
                        failures.append(error)

                try:
                    self._drain_bridges()
                except BaseException as error:
                    failures.append(error)

                for handle in tuple(self.active_bridges):
                    try:
                        self._channel().transact(
                            OP_BRIDGE_CANCEL,
                            handle,
                            allowed_statuses=(0, -errno.ENOENT),
                        )
                    except BaseException as error:
                        failures.append(error)
                for handle in tuple(self.active_bridges):
                    try:
                        if not self._join_bridge_result(
                            handle,
                            BRIDGE_SHUTDOWN_JOIN_MS,
                        ):
                            failures.append(
                                TimeoutError(
                                    f"bridge {handle} did not stop within "
                                    f"{BRIDGE_SHUTDOWN_JOIN_MS} ms"
                                )
                            )
                    except BaseException as error:
                        failures.append(error)
                    finally:
                        self.active_bridges.discard(handle)

                try:
                    self._channel().transact(OP_SHUTDOWN)
                    status = self.process.wait(timeout=self.shutdown_timeout)
                    if status != 0:
                        failures.append(
                            RuntimeExitedError(
                                f"hosted kernel shutdown returned status {status}"
                            )
                        )
                except BaseException as error:
                    failures.append(error)
            elif process_was_running:
                # Before successful L3 attach, the hosted FINISH-era initcall
                # cannot take the clean product exit. Terminate the child and
                # still release the host transaction below.
                self._force_stop()
            elif not process_was_running and self.process.poll() not in (0, None):
                failures.append(
                    RuntimeExitedError(
                        "hosted kernel was already dead during shutdown with "
                        f"status {self.process.poll()}"
                    )
                )
        finally:
            if self.process.poll() is None:
                try:
                    self._force_stop()
                except BaseException as error:
                    failures.append(error)
            try:
                self._close_pipe(self.process.stdin)
            except BaseException as error:
                failures.append(error)
            try:
                self._close_pipe(self.process.stdout)
            except BaseException as error:
                failures.append(error)

        if failures:
            raise RuntimeCleanupError(tuple(failures))


def run_service(
    config: ServiceConfig,
    *,
    emitter: EventEmitter | None = None,
    network_acquirer: NetworkAcquirer = acquire_host_network,
    process_factory: ProcessFactory = subprocess.Popen,
    control_factory: ControlFactory = ControlClient,
    signal_manager_factory: Callable[[], ShutdownSignals] = ShutdownSignals,
) -> int:
    """Acquire host state, run the listener, then unwind in strict order."""

    emitter = emitter or EventEmitter()
    network_config = host_network_config(config)
    iptables_path, restore_path, save_path = iptables_paths(
        config.iptables_variant,
        config.listen.version,
    )
    lease: HostNetworkLease | None = None
    runtime: HostedKernelRuntime | None = None
    primary: BaseException | None = None
    cleanup_failures: list[BaseException] = []
    ready = False
    requested_signal: int | None = None

    with signal_manager_factory() as stop:
        try:
            lease = network_acquirer(
                network_config,
                iptables_path=iptables_path,
                iptables_restore_path=restore_path,
                iptables_save_path=save_path,
            )
            if not stop.requested:
                runtime = HostedKernelRuntime(
                    config,
                    emitter=emitter,
                    process_factory=process_factory,
                    control_factory=control_factory,
                )
                runtime.start(lease.tun_fd)
                if not stop.requested:
                    emitter.event(
                        "ready",
                        listen=str(config.listen),
                        backend=str(config.backend),
                        cc=config.cc,
                        firewall_backend=lease.firewall_backend,
                        firewall_resource=lease.firewall_resource,
                        tun=lease.tun_name,
                        hosted_address=config.tun_guest_address,
                        hosted_ifindex=runtime.ifindex,
                        hosted_pid=runtime.pid,
                        hosted_memory_mib=config.memory_mib,
                        max_connections=config.max_connections,
                        shutdown_grace_period=config.shutdown_grace_period,
                    )
                    emitter.diagnostic(
                        f"ready on {config.listen} with {config.cc}; "
                        f"bridging to {config.backend} via {lease.tun_name}"
                    )
                    ready = True
                    runtime.serve(stop)
            requested_signal = stop.requested_signal
        except BaseException as error:
            primary = error
            requested_signal = stop.requested_signal
        finally:
            if runtime is not None:
                try:
                    runtime.shutdown()
                except BaseException as error:
                    cleanup_failures.append(error)
            if lease is not None:
                try:
                    lease.close()
                except BaseException as error:
                    cleanup_failures.append(error)

    if cleanup_failures:
        raise ServiceCleanupError(primary, tuple(cleanup_failures))
    if primary is not None:
        raise primary
    if ready:
        emitter.event(
            "stopped",
            signal=requested_signal,
            clean=True,
        )
        emitter.diagnostic("stopped cleanly")
    return 0


def main(
    argv: list[str] | None = None,
    *,
    environ: dict[str, str] | None = None,
) -> int:
    parser = build_parser(environ=environ)
    namespace = parser.parse_args(argv)
    try:
        config = config_from_namespace(namespace)
        return run_service(config)
    except (HostPreflightError, StaleOwnershipError) as error:
        print(error.report.to_json(), file=sys.stderr, flush=True)
        print(f"tcpcc: error: {error}", file=sys.stderr, flush=True)
        return 1
    except Exception as error:
        print(f"tcpcc: error: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

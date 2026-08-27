#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Deterministic tests for the stable tcpcc command and control path."""

from __future__ import annotations

import errno
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from tcpcc_cli import (  # noqa: E402
    BRIDGE_BUFFER_LIMIT,
    BRIDGE_SESSION_LIMIT,
    BRIDGE_TOTAL_BUFFER_LIMIT,
    ELF_HEADER,
    ELF_PROGRAM_HEADER,
    EM_X86_64,
    ET_EXEC,
    EventEmitter,
    Endpoint,
    HostedKernelRuntime,
    RuntimeExitedError,
    ServiceConfig,
    build_parser,
    config_from_namespace,
    main,
    run_service,
    validate_kernel_image,
)
from tcpcc_control import (  # noqa: E402
    BRIDGE_RESULT,
    MAGIC,
    MAX_PAYLOAD,
    OP_ACCEPT_NONBLOCK,
    OP_BIND,
    OP_BRIDGE_CANCEL,
    OP_BRIDGE_JOIN_RESULT,
    OP_BRIDGE_START,
    OP_CLOSE,
    OP_GET_CC,
    OP_L3_ATTACH,
    OP_LISTEN,
    OP_SET_CC,
    OP_SHUTDOWN,
    OP_SOCKET,
    REQUEST,
    RESPONSE,
    SERVICE_CONFIG,
    SERVICE_STATS,
    VERSION,
    ControlClient,
    ControlOperationError,
    ControlProtocolError,
    ControlResponse,
    decode_bridge_result,
    decode_response,
    decode_service_stats,
    encode_request,
    encode_service_config,
)
from tcpcc_host import (  # noqa: E402
    CheckResult,
    HostPreflightError,
    PreflightReport,
)


def write_test_elf(path: Path, *, program_type: int = 1) -> None:
    ident = bytearray(16)
    ident[:7] = b"\x7fELF\x02\x01\x01"
    header = ELF_HEADER.pack(
        bytes(ident),
        ET_EXEC,
        EM_X86_64,
        1,
        0x401000,
        ELF_HEADER.size,
        0,
        0,
        ELF_HEADER.size,
        ELF_PROGRAM_HEADER.size,
        1,
        0,
        0,
        0,
    )
    program = ELF_PROGRAM_HEADER.pack(
        program_type,
        5,
        0,
        0x400000,
        0x400000,
        0,
        0,
        0x1000,
    )
    path.write_bytes(header + program)
    path.chmod(0o700)


class ControlCodecTests(unittest.TestCase):
    def test_request_is_fixed_size_and_preserves_fields(self) -> None:
        encoded = encode_request(OP_BIND, 7, 0xCB00710A, 443, b"abc")

        self.assertEqual(len(encoded), REQUEST.size)
        magic, version, operation, handle, arg0, arg1, length, data = REQUEST.unpack(
            encoded
        )
        self.assertEqual(
            (magic, version, operation, handle, arg0, arg1, length),
            (MAGIC, VERSION, OP_BIND, 7, 0xCB00710A, 443, 3),
        )
        self.assertEqual(data[:3], b"abc")
        self.assertEqual(data[3:], bytes(MAX_PAYLOAD - 3))

    def test_request_rejects_oversize_and_out_of_range_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "ABI limit"):
            encode_request(OP_SET_CC, data=bytes(MAX_PAYLOAD + 1))
        with self.assertRaisesRegex(ValueError, "arg1"):
            encode_request(OP_BIND, arg1=1 << 32)
        with self.assertRaisesRegex(TypeError, "handle"):
            encode_request(OP_CLOSE, True)

    def test_response_rejects_wrong_header_and_oversize_payload(self) -> None:
        wrong_op = RESPONSE.pack(MAGIC, VERSION, OP_CLOSE, 0, 0, 0, bytes(256))
        with self.assertRaisesRegex(ControlProtocolError, "operation"):
            decode_response(wrong_op, OP_SOCKET)

        oversize = RESPONSE.pack(
            MAGIC,
            VERSION,
            OP_SOCKET,
            0,
            1,
            MAX_PAYLOAD + 1,
            bytes(256),
        )
        with self.assertRaisesRegex(ControlProtocolError, "maximum"):
            decode_response(oversize, OP_SOCKET)

    def test_control_client_handles_partial_response_and_errno(self) -> None:
        request_read, request_write = os.pipe()
        response_read, response_write = os.pipe()
        stdin = os.fdopen(request_write, "wb", buffering=0)
        stdout = os.fdopen(response_read, "rb", buffering=0)
        observed: list[bytes] = []

        def worker() -> None:
            try:
                observed.append(os.read(request_read, REQUEST.size))
                raw = RESPONSE.pack(
                    MAGIC,
                    VERSION,
                    OP_SOCKET,
                    0,
                    9,
                    0,
                    bytes(256),
                )
                os.write(response_write, raw[:17])
                os.write(response_write, raw[17:])
            finally:
                os.close(request_read)
                os.close(response_write)

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            response = ControlClient(stdin, stdout, timeout=1).transact(OP_SOCKET)
        finally:
            stdin.close()
            stdout.close()
            thread.join(1)

        self.assertFalse(thread.is_alive())
        self.assertEqual(response.handle, 9)
        self.assertEqual(observed, [encode_request(OP_SOCKET)])

    def test_bridge_result_rejects_reserved_fields(self) -> None:
        data = BRIDGE_RESULT.pack(
            1,
            2,
            3,
            BRIDGE_BUFFER_LIMIT,
            BRIDGE_TOTAL_BUFFER_LIMIT,
            0,
            0,
            0,
            0,
            BRIDGE_SESSION_LIMIT,
            0,
            1,
            0,
        )
        with self.assertRaisesRegex(ControlProtocolError, "reserved"):
            decode_bridge_result(data)

    def test_bridge_result_exposes_terminal_errno_only_when_requested(self) -> None:
        data = BRIDGE_RESULT.pack(
            1,
            2,
            3,
            BRIDGE_BUFFER_LIMIT,
            BRIDGE_TOTAL_BUFFER_LIMIT,
            1 << 3,
            4,
            5,
            6,
            BRIDGE_SESSION_LIMIT,
            -errno.ECONNRESET,
            0,
            0,
        )
        with self.assertRaisesRegex(ControlProtocolError, "status"):
            decode_bridge_result(data)
        result = decode_bridge_result(data, allow_terminal_error=True)
        self.assertEqual(result.status, -errno.ECONNRESET)
        self.assertEqual(result.host_send_eagain, 4)

    def test_hosted_service_config_and_stats_have_fixed_layouts(self) -> None:
        config = encode_service_config(0x7F000001, 8443, 8, 4)
        self.assertEqual(len(config), 16)
        self.assertEqual(
            SERVICE_CONFIG.unpack(config),
            (0x7F000001, 8443, 0, 8, 4),
        )

        raw = SERVICE_STATS.pack(
            11,
            10,
            1,
            1234,
            5678,
            1,
            3,
            8,
            4,
            7,
            1,
            2,
            2,
            -errno.ECONNRESET,
            0,
            0,
            0,
        )
        stats = decode_service_stats(raw)
        self.assertEqual(stats.accepted_connections, 11)
        self.assertEqual(stats.completed_connections, 10)
        self.assertEqual(stats.public_to_backend_bytes, 1234)
        self.assertEqual(stats.state, 2)
        self.assertEqual(stats.last_error, -errno.ECONNRESET)

    def test_hosted_service_stats_reject_reserved_and_positive_error(self) -> None:
        values = [0] * 17
        values[-1] = 1
        with self.assertRaisesRegex(ControlProtocolError, "reserved"):
            decode_service_stats(SERVICE_STATS.pack(*values))
        values[-1] = 0
        values[13] = 1
        with self.assertRaisesRegex(ControlProtocolError, "positive"):
            decode_service_stats(SERVICE_STATS.pack(*values))


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.kernel = Path(self.temp.name) / "vmlinux"
        write_test_elf(self.kernel)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def arguments(self, *extra: str) -> list[str]:
        return [
            "--listen",
            "203.0.113.10:443",
            "--backend",
            "127.0.0.1:8443",
            "--cc",
            "bbr",
            "--kernel",
            str(self.kernel),
            *extra,
        ]

    def test_target_command_parses_and_validates_before_mutation(self) -> None:
        namespace = build_parser(environ={}).parse_args(self.arguments())
        config = config_from_namespace(namespace)

        self.assertEqual(str(config.listen), "203.0.113.10:443")
        self.assertEqual(str(config.backend), "127.0.0.1:8443")
        self.assertEqual(config.cc, "bbr")
        self.assertEqual(config.kernel, self.kernel.resolve())
        self.assertEqual(config.firewall_backend, "nft-lib")
        self.assertEqual(config.max_connections, BRIDGE_SESSION_LIMIT)
        self.assertEqual(config.shutdown_grace_period, 5.0)

    def test_runtime_limits_are_explicit_and_bounded(self) -> None:
        namespace = build_parser(environ={}).parse_args(
            self.arguments(
                "--max-connections",
                "4",
                "--shutdown-grace-period",
                "1.25",
            )
        )
        config = config_from_namespace(namespace)
        self.assertEqual(config.max_connections, 4)
        self.assertEqual(config.shutdown_grace_period, 1.25)

        for arguments, message in (
            (("--max-connections", "9"), "max connections"),
            (("--shutdown-grace-period", "-1"), "grace period"),
        ):
            with self.subTest(arguments=arguments):
                invalid = build_parser(environ={}).parse_args(
                    self.arguments(*arguments)
                )
                with self.assertRaisesRegex(ValueError, message):
                    config_from_namespace(invalid)

    def test_endpoints_reject_forward_proxy_and_nonliteral_forms(self) -> None:
        invalid = (
            "nginx.example:443",
            "[2001:db8::1]:443",
            "203.0.113.10:0",
            "0.0.0.0:443",
            "224.0.0.1:443",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Endpoint.parse(value, "listen")

        namespace = build_parser(environ={}).parse_args(
            self.arguments()[0:2]
            + ["--backend", "127.0.0.2:8443"]
            + self.arguments()[4:]
        )
        with self.assertRaisesRegex(ValueError, "127.0.0.1"):
            config_from_namespace(namespace)

    def test_iptables_variant_requires_iptables_backend(self) -> None:
        namespace = build_parser(environ={}).parse_args(
            self.arguments("--iptables-variant", "iptables-legacy")
        )
        with self.assertRaisesRegex(ValueError, "valid only"):
            config_from_namespace(namespace)

    def test_kernel_validator_rejects_interpreter_and_non_executable(self) -> None:
        write_test_elf(self.kernel, program_type=3)
        with self.assertRaisesRegex(ValueError, "interpreter"):
            validate_kernel_image(self.kernel)

        write_test_elf(self.kernel)
        self.kernel.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "not executable"):
            validate_kernel_image(self.kernel)

    def test_main_reports_validation_error_without_traceback(self) -> None:
        arguments = self.arguments()
        arguments[5] = "INVALID!"
        stderr = io.StringIO()
        previous = sys.stderr
        sys.stderr = stderr
        try:
            status = main(arguments, environ={})
        finally:
            sys.stderr = previous
        self.assertEqual(status, 1)
        self.assertIn("tcpcc: error:", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_main_prints_complete_preflight_report_before_error(self) -> None:
        report = PreflightReport(
            requested_cc="bbr",
            checks=(
                CheckResult(
                    "sysctl.tcp_congestion_control",
                    "fail",
                    "required",
                    "cubic",
                    "bbr",
                    "set net.ipv4.tcp_congestion_control=bbr before startup",
                ),
            ),
        )
        stderr = io.StringIO()
        previous = sys.stderr
        sys.stderr = stderr
        try:
            with patch(
                "tcpcc_cli.run_service",
                side_effect=HostPreflightError(report),
            ):
                status = main(self.arguments(), environ={})
        finally:
            sys.stderr = previous

        self.assertEqual(status, 1)
        lines = stderr.getvalue().splitlines()
        document = json.loads(lines[0])
        self.assertEqual(document["schema"], "tcpcc.host-preflight.v1")
        self.assertFalse(document["ok"])
        self.assertIn("tcpcc: error: host preflight failed", lines[1])


class FakePipe:
    def __init__(self, process: FakeProcess) -> None:
        self.process = process
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeProcess:
    def __init__(self) -> None:
        self.status: int | None = None
        self.pid = 4242
        self.stdin = FakePipe(self)
        self.stdout = FakePipe(self)
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.status

    def wait(self, timeout: float | None = None) -> int:
        if self.status is None:
            raise subprocess.TimeoutExpired("fake-vmlinux", timeout)
        return self.status

    def terminate(self) -> None:
        self.terminated = True
        self.status = -signal.SIGTERM

    def kill(self) -> None:
        self.killed = True
        self.status = -signal.SIGKILL


class FakeControl:
    def __init__(
        self,
        process: FakeProcess,
        *,
        cc: str = "bbr",
        accepted_cc: str | None = None,
        accept_once: bool = True,
        accept_limit: int | None = None,
        terminal_status: int = 0,
        terminal_events: int = 0,
        complete_after_join_calls: int | None = 2,
    ) -> None:
        self.process = process
        self.cc = cc
        self.accepted_cc = cc if accepted_cc is None else accepted_cc
        self.accept_limit = (
            1 if accept_once else 0
        ) if accept_limit is None else accept_limit
        self.accepted_count = 0
        self.cancelled: set[int] = set()
        self.join_calls: dict[int, int] = {}
        self.terminal_status = terminal_status
        self.terminal_events = terminal_events
        self.complete_after_join_calls = complete_after_join_calls
        self.operations: list[tuple[int, int, int, int, bytes]] = []

    def _bridge_data(
        self,
        *,
        status: int | None = None,
        terminal_events: int | None = None,
    ) -> bytes:
        return BRIDGE_RESULT.pack(
            0x8000000100000002,
            123,
            456,
            BRIDGE_BUFFER_LIMIT,
            BRIDGE_TOTAL_BUFFER_LIMIT,
            self.terminal_events if terminal_events is None else terminal_events,
            3,
            0,
            0,
            BRIDGE_SESSION_LIMIT,
            self.terminal_status if status is None else status,
            0,
            0,
        )

    @staticmethod
    def _return(
        operation: int,
        status: int,
        handle: int,
        data: bytes,
        allowed_statuses: tuple[int, ...],
    ) -> ControlResponse:
        if status not in allowed_statuses:
            raise ControlOperationError(operation, status)
        return ControlResponse(operation, status, handle, data)

    def transact(
        self,
        operation: int,
        handle: int = 0,
        arg0: int = 0,
        arg1: int = 0,
        data: bytes = b"",
        *,
        allowed_statuses: tuple[int, ...] = (0,),
    ) -> ControlResponse:
        self.operations.append((operation, handle, arg0, arg1, data))
        status = 0
        response_handle = handle
        response_data = b""
        if operation == OP_L3_ATTACH:
            response_handle = 7
        elif operation == OP_SOCKET:
            response_handle = 1
        elif operation == OP_GET_CC:
            response_data = (
                self.accepted_cc if handle != 1 else self.cc
            ).encode("ascii")
        elif operation == OP_ACCEPT_NONBLOCK:
            if self.accepted_count < self.accept_limit:
                self.accepted_count += 1
                response_handle = 1 + self.accepted_count
            else:
                status = -errno.EAGAIN
        elif operation == OP_BRIDGE_START:
            response_handle = 15 + handle
        elif operation == OP_BRIDGE_CANCEL:
            self.cancelled.add(handle)
        elif operation == OP_BRIDGE_JOIN_RESULT:
            self.join_calls[handle] = self.join_calls.get(handle, 0) + 1
            if handle in self.cancelled:
                response_data = self._bridge_data(status=-errno.ECANCELED)
            elif (
                self.complete_after_join_calls is None
                or self.join_calls[handle] < self.complete_after_join_calls
            ):
                status = -errno.ETIMEDOUT
            else:
                response_data = self._bridge_data()
        elif operation == OP_SHUTDOWN:
            self.process.status = 0
        elif operation not in {
            OP_SET_CC,
            OP_BIND,
            OP_LISTEN,
            OP_CLOSE,
        }:
            raise AssertionError(f"unexpected fake operation {operation}")
        return self._return(
            operation,
            status,
            response_handle,
            response_data,
            allowed_statuses,
        )


def runtime_config(kernel: Path, **options: object) -> ServiceConfig:
    return ServiceConfig(
        listen=Endpoint("203.0.113.10", 443),
        backend=Endpoint("127.0.0.1", 8443),
        cc="bbr",
        kernel=kernel,
        **options,
    )


class RuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.output = io.StringIO()
        self.diagnostics = io.StringIO()
        self.emitter = EventEmitter(
            output=self.output,
            diagnostics=self.diagnostics,
        )
        self.process = FakeProcess()
        self.control = FakeControl(self.process)

    def runtime(
        self,
        control: FakeControl | None = None,
        runtime_clock: object | None = None,
        **config_options: object,
    ) -> HostedKernelRuntime:
        selected = self.control if control is None else control
        runtime_options = {}
        if runtime_clock is not None:
            runtime_options["clock"] = runtime_clock
        return HostedKernelRuntime(
            runtime_config(Path("/fixture/vmlinux"), **config_options),
            emitter=self.emitter,
            process_factory=lambda *_args, **_kwargs: self.process,
            control_factory=lambda _stdin, _stdout: selected,
            **runtime_options,
        )

    def test_start_sets_listener_cc_before_bind_and_listen(self) -> None:
        runtime = self.runtime()
        runtime.start(101)

        operations = [entry[0] for entry in self.control.operations]
        self.assertEqual(
            operations,
            [OP_L3_ATTACH, OP_SOCKET, OP_SET_CC, OP_GET_CC, OP_BIND, OP_LISTEN],
        )
        l3 = self.control.operations[0]
        self.assertEqual((l3[1], l3[2], l3[3]), (101, 0xC6120002, 32))
        self.assertEqual(self.control.operations[2][4], b"bbr")
        self.assertEqual(runtime.ifindex, 7)

    def test_poll_verifies_inheritance_and_reaps_completed_bridge(self) -> None:
        runtime = self.runtime()
        runtime.start(101)

        runtime.poll_once()
        self.assertEqual(runtime.active_bridges, {17})
        runtime.poll_once()
        self.assertEqual(runtime.active_bridges, {17})
        runtime.poll_once()
        self.assertEqual(runtime.active_bridges, set())

        accepted_get = [
            entry
            for entry in self.control.operations
            if entry[0] == OP_GET_CC and entry[1] == 2
        ]
        self.assertEqual(len(accepted_get), 1)
        event = json.loads(self.output.getvalue().splitlines()[-1])
        self.assertEqual(event["event"], "connection-closed")
        self.assertEqual(event["public_to_backend_bytes"], 123)
        self.assertEqual(event["host_send_eagain"], 3)

    def test_inheritance_mismatch_closes_accepted_socket(self) -> None:
        control = FakeControl(self.process, accepted_cc="cubic")
        runtime = self.runtime(control)
        runtime.start(101)

        with self.assertRaisesRegex(ControlProtocolError, "expected 'bbr'"):
            runtime.poll_once()

        self.assertIn((OP_CLOSE, 2, 0, 0, b""), control.operations)
        self.assertEqual(runtime.active_bridges, set())

    def test_shutdown_closes_listener_cancels_session_then_exits_zero(self) -> None:
        runtime = self.runtime(shutdown_grace_period=0)
        runtime.start(101)
        runtime.poll_once()

        runtime.shutdown()

        operations = [entry[0] for entry in self.control.operations]
        close_index = max(
            index
            for index, entry in enumerate(self.control.operations)
            if entry[0] == OP_CLOSE and entry[1] == 1
        )
        cancel_index = operations.index(OP_BRIDGE_CANCEL)
        shutdown_index = operations.index(OP_SHUTDOWN)
        self.assertLess(close_index, cancel_index)
        self.assertLess(cancel_index, shutdown_index)
        self.assertEqual(self.process.status, 0)
        self.assertTrue(self.process.stdin.closed)
        self.assertTrue(self.process.stdout.closed)

    def test_shutdown_drains_completed_session_before_hosted_exit(self) -> None:
        runtime = self.runtime()
        runtime.start(101)
        runtime.poll_once()

        runtime.shutdown()

        operations = [entry[0] for entry in self.control.operations]
        self.assertNotIn(OP_BRIDGE_CANCEL, operations)
        self.assertLess(
            operations.index(OP_BRIDGE_JOIN_RESULT),
            operations.index(OP_SHUTDOWN),
        )
        documents = [
            json.loads(line) for line in self.output.getvalue().splitlines()
        ]
        self.assertIn("draining", [document["event"] for document in documents])
        self.assertEqual(documents[-1]["event"], "connection-closed")
        self.assertEqual(documents[-1]["status"], 0)

    def test_shutdown_cancels_only_after_grace_period_expires(self) -> None:
        control = FakeControl(
            self.process,
            complete_after_join_calls=None,
        )
        now = 0.0

        def clock() -> float:
            nonlocal now
            now += 0.05
            return now

        runtime = self.runtime(
            control,
            runtime_clock=clock,
            shutdown_grace_period=0.15,
        )
        runtime.start(101)
        runtime.poll_once()

        runtime.shutdown()

        operations = [entry[0] for entry in control.operations]
        self.assertIn(OP_BRIDGE_CANCEL, operations)
        documents = [
            json.loads(line) for line in self.output.getvalue().splitlines()
        ]
        events = [document["event"] for document in documents]
        self.assertIn("drain-timeout", events)
        closed = next(
            document for document in documents
            if document["event"] == "connection-closed"
        )
        self.assertEqual(closed["status"], -errno.ECANCELED)

    def test_capacity_stops_accepting_at_configured_limit(self) -> None:
        control = FakeControl(self.process, accept_limit=3)
        runtime = self.runtime(
            control,
            max_connections=2,
            shutdown_grace_period=0,
        )
        runtime.start(101)

        runtime.poll_once()

        self.assertEqual(runtime.active_bridges, {17, 18})
        accepts = [
            entry for entry in control.operations
            if entry[0] == OP_ACCEPT_NONBLOCK
        ]
        self.assertEqual(len(accepts), 2)
        opened = [
            json.loads(line)
            for line in self.output.getvalue().splitlines()
            if json.loads(line)["event"] == "connection-opened"
        ]
        self.assertEqual([event["active_connections"] for event in opened], [1, 2])
        runtime.shutdown()

    def test_terminal_reset_is_reported_without_stopping_runtime(self) -> None:
        control = FakeControl(
            self.process,
            terminal_status=-errno.ECONNRESET,
            terminal_events=1 << 3,
        )
        runtime = self.runtime(control)
        runtime.start(101)
        runtime.poll_once()
        runtime.poll_once()
        runtime.poll_once()

        self.assertEqual(runtime.active_bridges, set())
        self.assertIsNone(self.process.poll())
        closed = json.loads(self.output.getvalue().splitlines()[-1])
        self.assertEqual(closed["status"], -errno.ECONNRESET)
        self.assertEqual(closed["terminal_events"], 1 << 3)
        runtime.shutdown()

    def test_unexpected_child_exit_is_runtime_failure(self) -> None:
        runtime = self.runtime()
        runtime.start(101)
        self.process.status = 86

        with self.assertRaisesRegex(RuntimeExitedError, "status 86"):
            runtime.poll_once()


class FakeStop:
    def __init__(self) -> None:
        self._requested = False
        self._signal: int | None = None

    @property
    def requested(self) -> bool:
        return self._requested

    @property
    def requested_signal(self) -> int | None:
        return self._signal

    def wait(self, _timeout: float | None = None) -> bool:
        self._requested = True
        self._signal = signal.SIGTERM
        return True

    def __enter__(self) -> FakeStop:
        return self

    def __exit__(self, *_args: object) -> None:
        pass


class FakeLease:
    def __init__(self, process: FakeProcess, events: list[str]) -> None:
        self.process = process
        self.events = events
        self.tun_fd = 101
        self.tun_name = "tcpcc-unit0"
        self.firewall_backend = "nft-lib"
        self.firewall_resource = "tcpcc_unit"
        self.closed = False

    def close(self) -> None:
        self.events.append(f"lease-close:child={self.process.poll()}")
        self.closed = True


class ServiceTransactionTests(unittest.TestCase):
    def test_signal_shutdown_stops_kernel_before_host_lease(self) -> None:
        process = FakeProcess()
        control = FakeControl(process, accept_once=False)
        events: list[str] = []
        lease = FakeLease(process, events)
        output = io.StringIO()
        diagnostics = io.StringIO()
        emitter = EventEmitter(output=output, diagnostics=diagnostics)

        def acquire(_config: object, **paths: str) -> FakeLease:
            events.append("lease-acquire")
            self.assertEqual(paths["iptables_path"], "iptables")
            return lease

        status = run_service(
            runtime_config(Path("/fixture/vmlinux")),
            emitter=emitter,
            network_acquirer=acquire,
            process_factory=lambda *_args, **_kwargs: process,
            control_factory=lambda _stdin, _stdout: control,
            signal_manager_factory=FakeStop,
        )

        self.assertEqual(status, 0)
        self.assertEqual(events, ["lease-acquire", "lease-close:child=0"])
        self.assertTrue(lease.closed)
        documents = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([document["event"] for document in documents], ["ready", "stopped"])
        self.assertEqual(documents[0]["cc"], "bbr")
        self.assertEqual(documents[1]["signal"], signal.SIGTERM)
        self.assertIn("stopped cleanly", diagnostics.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)

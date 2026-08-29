#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unit and fault-injection matrix for all tcpcc firewall paths."""

from __future__ import annotations

import errno
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import tcpcc_host  # noqa: E402
from tcpcc_host import (  # noqa: E402
    CleanupError,
    HostInspector,
    IptablesFirewallBackend,
    IptablesInstallRollbackError,
    LibNftablesError,
    LibNftablesTransport,
    NftDnatConfig,
    NftExecTransport,
    NftFirewallBackend,
    NftOwnership,
    collect_preflight,
    create_firewall_backend,
)


def config(*, table_name: str | None = None) -> NftDnatConfig:
    return NftDnatConfig(
        listen_address="203.0.113.10",
        listen_port=443,
        target_address="198.18.0.2",
        target_port=28443,
        table_name=table_name,
    )


def config_ipv6(*, table_name: str | None = None) -> NftDnatConfig:
    return NftDnatConfig(
        listen_address="2001:db8::10",
        listen_port=443,
        target_address="fd00:198:18::2",
        target_port=28443,
        table_name=table_name,
    )


def owner(
    *,
    pid: int = 123,
    start_time: int = 456,
    tun_name: str = "tcpcc-unit0",
) -> NftOwnership:
    return NftOwnership(pid=pid, start_time=start_time, tun_name=tun_name)


def proc_stat(pid: int, start_time: int) -> str:
    fields = ["S", *(["0"] * 18), str(start_time)]
    return f"{pid} (tcpcc worker) " + " ".join(fields) + "\n"


class RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.outputs: dict[tuple[str, ...], str] = {}
        self.failures: dict[tuple[str, ...], BaseException] = {}

    def __call__(self, argv: list[str], input_text: str | None) -> str:
        self.calls.append((list(argv), input_text))
        key = tuple(argv)
        if key in self.failures:
            raise self.failures[key]
        return self.outputs.get(key, "")


class FakeFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *arguments):
        return self.callback(*arguments)


class FakeLibNftables:
    def __init__(self, *, run_code: int = 0, stderr: bytes = b"") -> None:
        self.calls: list[tuple[str, object]] = []
        self.run_code = run_code
        self.stdout = b""
        self.stderr = stderr
        self.dry_run = False
        self.json_output = False
        self.nft_ctx_new = FakeFunction(self._new)
        self.nft_ctx_free = FakeFunction(self._free)
        self.nft_ctx_buffer_output = FakeFunction(lambda _ctx: 0)
        self.nft_ctx_buffer_error = FakeFunction(lambda _ctx: 0)
        self.nft_ctx_get_output_buffer = FakeFunction(lambda _ctx: self.stdout)
        self.nft_ctx_get_error_buffer = FakeFunction(lambda _ctx: self.stderr)
        self.nft_ctx_set_dry_run = FakeFunction(self._set_dry_run)
        self.nft_ctx_output_set_json = FakeFunction(self._set_json)
        self.nft_run_cmd_from_buffer = FakeFunction(self._run)

    def _new(self, flags: int) -> int:
        self.calls.append(("new", flags))
        return 101

    def _free(self, context: int) -> None:
        self.calls.append(("free", context))

    def _set_dry_run(self, _context: int, enabled: bool) -> None:
        self.dry_run = bool(enabled)

    def _set_json(self, _context: int, enabled: bool) -> None:
        self.json_output = bool(enabled)

    def _run(self, _context: int, command: bytes) -> int:
        decoded = command.decode("utf-8")
        self.calls.append(("run", decoded))
        if decoded == "list ruleset ip\n":
            self.stdout = b'{"nftables":[]}'
        else:
            self.stdout = b""
        return self.run_code


class FirewallBackendTests(unittest.TestCase):
    def test_nft_exec_uses_only_exact_argv_and_stdin(self) -> None:
        runner = RecordingRunner()
        runner.outputs[("/usr/sbin/nft", "--json", "list", "ruleset", "ip")] = (
            '{"nftables":[]}'
        )
        transport = NftExecTransport("/usr/sbin/nft", runner=runner)

        transport.run(
            ["/usr/sbin/nft", "--check", "--file", "-"],
            "create table ip tcpcc_probe\n",
        )
        output = transport.read(
            ["/usr/sbin/nft", "--json", "list", "ruleset", "ip"]
        )

        self.assertEqual(output, '{"nftables":[]}')
        self.assertEqual(
            runner.calls,
            [
                (
                    ["/usr/sbin/nft", "--check", "--file", "-"],
                    "create table ip tcpcc_probe\n",
                ),
                (
                    [
                        "/usr/sbin/nft",
                        "--json",
                        "list",
                        "ruleset",
                        "ip",
                    ],
                    None,
                ),
            ],
        )

    def test_libnftables_apply_dry_run_json_and_delete_without_exec(self) -> None:
        library = FakeLibNftables()
        transport = LibNftablesTransport(
            finder=lambda _name: "/fixture/libnftables.so",
            loader=lambda _path: library,
        )

        with mock.patch.object(tcpcc_host.subprocess, "run") as run:
            transport.run(
                ["libnftables", "--file", "-"],
                "create table ip tcpcc_case\n",
            )
            transport.run(
                ["libnftables", "--check", "--file", "-"],
                "create table ip tcpcc_probe\n",
            )
            output = transport.read(
                ["libnftables", "--json", "list", "ruleset", "ip"]
            )
            transport.run(
                ["libnftables", "delete", "table", "ip", "tcpcc_case"],
                None,
            )

        run.assert_not_called()
        self.assertEqual(output, '{"nftables":[]}')
        commands = [value for operation, value in library.calls if operation == "run"]
        self.assertEqual(
            commands,
            [
                "create table ip tcpcc_case\n",
                "create table ip tcpcc_probe\n",
                "list ruleset ip\n",
                "delete table ip tcpcc_case\n",
            ],
        )
        self.assertEqual(
            sum(operation == "free" for operation, _value in library.calls),
            4,
        )
        self.assertTrue(library.json_output)

    def test_libnftables_error_preserves_diagnostic_and_frees_context(self) -> None:
        library = FakeLibNftables(run_code=-1, stderr=b"Operation not permitted")
        transport = LibNftablesTransport(
            finder=lambda _name: "libnftables.so.1",
            loader=lambda _path: library,
        )

        with self.assertRaises(LibNftablesError) as raised:
            transport.run(
                ["libnftables", "--file", "-"],
                "create table ip tcpcc_case\n",
            )

        self.assertEqual(raised.exception.return_code, -1)
        self.assertIn("Operation not permitted", str(raised.exception))
        self.assertEqual(library.calls[-1], ("free", 101))

    def test_libnftables_rejects_unknown_runner_shapes_before_calling_c(self) -> None:
        library = FakeLibNftables()
        transport = LibNftablesTransport(
            finder=lambda _name: "libnftables.so.1",
            loader=lambda _path: library,
        )

        with self.assertRaises(ValueError):
            transport.run(["libnftables", "flush", "ruleset"], None)
        with self.assertRaises(ValueError):
            transport.read(["libnftables", "list", "tables"])
        self.assertEqual(library.calls, [])

    def test_both_nft_transports_render_the_same_owned_atomic_batch(self) -> None:
        calls: dict[str, list[tuple[list[str], str | None]]] = {
            "nft-exec": [],
            "nft-lib": [],
        }

        class Transport:
            command_name = "fixture"

            def __init__(self, backend_id: str) -> None:
                self.backend_id = backend_id

            def run(self, argv, input_text) -> None:
                calls[self.backend_id].append((list(argv), input_text))

            def read(self, _argv) -> str:
                return '{"nftables":[]}'

        for backend_id in ("nft-exec", "nft-lib"):
            backend = NftFirewallBackend(Transport(backend_id))
            lease = backend.install(config(table_name="tcpcc_case"), owner())
            lease.close()

        exec_batch = calls["nft-exec"][0][1]
        lib_batch = calls["nft-lib"][0][1]
        self.assertEqual(exec_batch, lib_batch)
        self.assertIn("ip daddr 203.0.113.10", exec_batch or "")
        self.assertIn("tcp dport 443", exec_batch or "")
        self.assertIn(owner().marker(), exec_batch or "")
        self.assertNotIn("flush", exec_batch or "")

    def test_ipv6_nft_and_ip6tables_render_exact_family_rules(self) -> None:
        calls: list[tuple[list[str], str | None]] = []

        class Transport:
            backend_id = "nft-exec"
            command_name = "nft"

            def run(self, argv, input_text) -> None:
                calls.append((list(argv), input_text))

            def read(self, _argv) -> str:
                return '{"nftables":[]}'

        nft = NftFirewallBackend(Transport(), "ip6")
        nft_lease = nft.install(config_ipv6(table_name="tcpcc_v6"), owner())
        nft_lease.close()
        batch = calls[0][1] or ""
        self.assertIn("create table ip6 tcpcc_v6", batch)
        self.assertIn("ip6 daddr 2001:db8::10", batch)
        self.assertIn("dnat to [fd00:198:18::2]:28443", batch)
        self.assertEqual(calls[1][0], ["nft", "delete", "table", "ip6", "tcpcc_v6"])

        runner = RecordingRunner()
        ip6tables = IptablesFirewallBackend(
            iptables_path="ip6tables-nft",
            restore_path="ip6tables-nft-restore",
            save_path="ip6tables-nft-save",
            runner=runner,
            chain_name_factory=lambda: "TCPCC_abcdef123456",
        )
        ip6tables.check_compatibility(config_ipv6())
        rendered = runner.calls[0][1] or ""
        self.assertIn("-d 2001:db8::10/128", rendered)
        self.assertIn("--to-destination [fd00:198:18::2]:28443", rendered)

    def test_iptables_check_install_and_cleanup_are_exact_and_ordered(self) -> None:
        runner = RecordingRunner()
        backend = IptablesFirewallBackend(
            iptables_path="/usr/sbin/iptables-legacy",
            restore_path="/usr/sbin/iptables-legacy-restore",
            save_path="/usr/sbin/iptables-legacy-save",
            runner=runner,
            chain_name_factory=lambda: "TCPCC_abcdef123456",
        )

        backend.check_compatibility(config())
        lease = backend.install(config(), owner())
        lease.close()
        lease.close()

        check_argv, check_batch = runner.calls[0]
        self.assertEqual(
            check_argv,
            [
                "/usr/sbin/iptables-legacy-restore",
                "--wait",
                "--test",
                "--noflush",
            ],
        )
        self.assertIn(":TCPCC_abcdef123456 - [0:0]", check_batch or "")
        self.assertIn("-A PREROUTING -d 203.0.113.10/32", check_batch or "")
        self.assertIn("--dport 443", check_batch or "")
        self.assertIn("-j TCPCC_abcdef123456", check_batch or "")

        self.assertEqual(
            runner.calls[1][0],
            [
                "/usr/sbin/iptables-legacy",
                "--wait",
                "-t",
                "nat",
                "-N",
                "TCPCC_abcdef123456",
            ],
        )
        install_argv, install_batch = runner.calls[2]
        self.assertEqual(
            install_argv,
            [
                "/usr/sbin/iptables-legacy-restore",
                "--wait",
                "--noflush",
            ],
        )
        self.assertNotIn(":TCPCC_abcdef123456", install_batch or "")
        self.assertIn(owner().marker(), install_batch or "")
        self.assertEqual(
            [call[0][4] for call in runner.calls[3:]],
            ["-D", "-F", "-X"],
        )
        self.assertEqual(len(runner.calls), 6)

    def test_iptables_create_collision_never_adopts_or_cleans_chain(self) -> None:
        runner = RecordingRunner()
        create_argv = (
            "iptables",
            "--wait",
            "-t",
            "nat",
            "-N",
            "tcpcc_taken",
        )
        collision = subprocess.CalledProcessError(1, create_argv, stderr="exists")
        runner.failures[create_argv] = collision
        backend = IptablesFirewallBackend(
            runner=runner,
            chain_name_factory=lambda: "TCPCC_unused0000",
        )

        with self.assertRaises(subprocess.CalledProcessError) as raised:
            backend.install(config(table_name="tcpcc_taken"), owner())

        self.assertIs(raised.exception, collision)
        self.assertEqual(runner.calls, [(list(create_argv), None)])

    def test_iptables_restore_failure_rolls_back_private_chain(self) -> None:
        runner = RecordingRunner()
        restore_argv = (
            "iptables-restore",
            "--wait",
            "--noflush",
        )
        rejected = subprocess.CalledProcessError(2, restore_argv, stderr="bad rule")
        runner.failures[restore_argv] = rejected
        backend = IptablesFirewallBackend(
            runner=runner,
            chain_name_factory=lambda: "TCPCC_abcdef123456",
        )

        with self.assertRaises(subprocess.CalledProcessError) as raised:
            backend.install(config(), owner())

        self.assertIs(raised.exception, rejected)
        self.assertEqual(
            [call[0][4] for call in runner.calls[2:]],
            ["-F", "-X"],
        )

    def test_iptables_restore_and_rollback_errors_are_both_preserved(self) -> None:
        runner = RecordingRunner()
        restore_argv = ("iptables-restore", "--wait", "--noflush")
        runner.failures[restore_argv] = OSError(errno.EINVAL, "restore failed")
        flush_argv = (
            "iptables",
            "--wait",
            "-t",
            "nat",
            "-F",
            "TCPCC_abcdef123456",
        )
        delete_argv = (*flush_argv[:4], "-X", flush_argv[5])
        runner.failures[flush_argv] = OSError(errno.EIO, "flush failed")
        runner.failures[delete_argv] = OSError(errno.EBUSY, "delete failed")
        backend = IptablesFirewallBackend(
            runner=runner,
            chain_name_factory=lambda: "TCPCC_abcdef123456",
        )

        with self.assertRaises(IptablesInstallRollbackError) as raised:
            backend.install(config(), owner())

        self.assertEqual(len(raised.exception.cleanup_errors), 2)
        self.assertIn("restore failed", str(raised.exception))
        self.assertIn("flush failed", str(raised.exception))
        self.assertIn("delete failed", str(raised.exception))

    def test_iptables_close_attempts_every_cleanup_after_failures(self) -> None:
        runner = RecordingRunner()
        backend = IptablesFirewallBackend(
            runner=runner,
            chain_name_factory=lambda: "TCPCC_abcdef123456",
        )
        lease = backend.install(config(), owner())
        for action in ("-D", "-F", "-X"):
            for argv, _input in list(runner.calls):
                if len(argv) > 4 and argv[4] == action:
                    runner.failures[tuple(argv)] = OSError(errno.EIO, action)
        # Cleanup calls have not happened yet, so inject by their exact forms.
        jump = tcpcc_host._iptables_rules(  # noqa: SLF001
            config(), "TCPCC_abcdef123456", owner()
        )[0]
        cleanup_commands = [
            (
                "iptables",
                "--wait",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                *jump,
            ),
            (
                "iptables",
                "--wait",
                "-t",
                "nat",
                "-F",
                "TCPCC_abcdef123456",
            ),
            (
                "iptables",
                "--wait",
                "-t",
                "nat",
                "-X",
                "TCPCC_abcdef123456",
            ),
        ]
        for command in cleanup_commands:
            runner.failures[command] = OSError(errno.EIO, command[4])

        with self.assertRaises(CleanupError) as raised:
            lease.close()

        self.assertEqual(len(raised.exception.failures), 3)
        self.assertEqual(
            [call[0][4] for call in runner.calls[-3:]],
            ["-D", "-F", "-X"],
        )
        lease.close()
        self.assertEqual(len(runner.calls), 5)

    def test_iptables_read_only_scan_classifies_and_preserves_unrelated(self) -> None:
        runner = RecordingRunner()
        save_argv = ("iptables-save", "-t", "nat")
        runner.outputs[save_argv] = "\n".join(
            (
                "*nat",
                ":PREROUTING ACCEPT [0:0]",
                ":TCPCC_000000000001 - [0:0]",
                ":TCPCC_000000000002 - [0:0]",
                ":TCPCC_000000000003 - [0:0]",
                ":unrelated - [0:0]",
                (
                    "-A TCPCC_000000000001 -m comment --comment "
                    '"tcpcc.owner.v1 pid=10 start=100 tun=tcpcc-a0" -j DNAT'
                ),
                (
                    "-A TCPCC_000000000002 -m comment --comment "
                    '"tcpcc.owner.v1 pid=11 start=110 tun=tcpcc-b0" -j DNAT'
                ),
                "-A unrelated -j RETURN",
                "COMMIT",
                "",
            )
        )

        def reader(path: Path) -> str:
            pid = int(path.parent.name)
            if pid == 10:
                return proc_stat(10, 100)
            raise FileNotFoundError(path)

        backend = IptablesFirewallBackend(
            runner=runner,
            proc_root=Path("/fixture/proc"),
            reader=reader,
        )
        report = backend.inspect_ownership()

        self.assertEqual(runner.calls, [(["iptables-save", "-t", "nat"], None)])
        self.assertTrue(report.blocking)
        self.assertEqual(
            [(item.chain_name, item.status) for item in report.observations],
            [
                ("TCPCC_000000000001", "active"),
                ("TCPCC_000000000002", "stale"),
                ("TCPCC_000000000003", "malformed"),
            ],
        )
        self.assertNotIn("unrelated", report.to_json())
        self.assertIn("iptables -t nat -F TCPCC_000000000002", report.to_json())

    def test_backend_specific_preflight_never_runs_a_command(self) -> None:
        operations: list[tuple[str, str]] = []
        values = {
            "self/status": "CapEff:\t0000000000001000\n",
            "sys/net/ipv4/ip_forward": "1\n",
            "sys/net/ipv4/tcp_congestion_control": "cubic\n",
            "sys/net/ipv4/tcp_available_congestion_control": "cubic\n",
            "sys/net/ipv4/conf/all/rp_filter": "0\n",
            "sys/net/ipv4/conf/default/rp_filter": "0\n",
        }

        def reader(path: Path) -> str:
            operations.append(("read", str(path)))
            return values[str(path.relative_to("/fixture/proc"))]

        def resolver(name: str) -> str:
            operations.append(("resolve", name))
            return f"/usr/sbin/{name}"

        def library_resolver(name: str) -> str:
            operations.append(("library", name))
            return "libnftables.so.1"

        class Device:
            st_mode = 0o020000

        inspector = HostInspector(
            proc_root=Path("/fixture/proc"),
            dev_root=Path("/fixture/dev"),
            reader=reader,
            resolver=resolver,
            library_resolver=library_resolver,
            statter=lambda _path: Device(),
            access=lambda _path, _mode: True,
        )

        reports = {
            backend: collect_preflight(
                "cubic", inspector, firewall_backend=backend
            )
            for backend in ("nft-lib", "nft-exec", "iptables")
        }

        self.assertTrue(all(report.ok for report in reports.values()))
        self.assertIn(
            "library.nftables",
            {check.check_id for check in reports["nft-lib"].checks},
        )
        self.assertEqual(
            {
                check.check_id
                for check in reports["iptables"].checks
                if check.check_id.startswith("tool.iptables")
            },
            {"tool.iptables", "tool.iptables-restore", "tool.iptables-save"},
        )
        self.assertNotIn("command", {kind for kind, _value in operations})

        operations.clear()
        variant_report = collect_preflight(
            "cubic",
            inspector,
            firewall_backend="iptables",
            iptables_path="iptables-legacy",
            iptables_restore_path="iptables-legacy-restore",
            iptables_save_path="iptables-legacy-save",
        )
        self.assertTrue(variant_report.ok)
        self.assertEqual(
            {
                check.check_id
                for check in variant_report.checks
                if check.check_id.startswith("tool.iptables")
            },
            {"tool.iptables", "tool.iptables-restore", "tool.iptables-save"},
        )
        self.assertTrue(
            {
                "iptables-legacy",
                "iptables-legacy-restore",
                "iptables-legacy-save",
            }.issubset(
                {value for kind, value in operations if kind == "resolve"}
            )
        )

    def test_backend_factory_is_explicit_and_never_silently_falls_back(self) -> None:
        self.assertEqual(create_firewall_backend("nft-exec").backend_id, "nft-exec")
        self.assertEqual(create_firewall_backend("nft-lib").backend_id, "nft-lib")
        self.assertEqual(create_firewall_backend("iptables").backend_id, "iptables")
        with self.assertRaises(ValueError):
            create_firewall_backend("auto")


if __name__ == "__main__":
    unittest.main(verbosity=2)

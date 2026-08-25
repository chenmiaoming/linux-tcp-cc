#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the M8.3 exact nftables DNAT lifecycle."""

from __future__ import annotations

import errno
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
    NftDnatConfig,
    OwnershipJournal,
    install_nft_dnat,
)


EXPECTED_BATCH = (
    "create table ip tcpcc_case\n"
    "add chain ip tcpcc_case prerouting "
    "{ type nat hook prerouting priority dstnat; policy accept; }\n"
    "add rule ip tcpcc_case prerouting "
    "ip daddr 203.0.113.10 tcp dport 443 counter "
    "dnat to 198.18.0.2:28443\n"
)


class NftFixture:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.events: list[str] = []
        self.install_error: BaseException | None = None
        self.delete_error: BaseException | None = None

    def runner(self, argv: list[str], input_text: str | None) -> None:
        self.calls.append((list(argv), input_text))
        if input_text is None:
            self.events.append("dnat-delete")
            if self.delete_error is not None:
                raise self.delete_error
        else:
            self.events.append("dnat-install")
            if self.install_error is not None:
                raise self.install_error

    def install(self, table_name: str | None = "tcpcc_case"):
        return install_nft_dnat(
            NftDnatConfig(
                listen_address="203.0.113.10",
                listen_port=443,
                target_address="198.18.0.2",
                target_port=28443,
                table_name=table_name,
            ),
            nft_path="/usr/sbin/nft",
            runner=self.runner,
            table_name_factory=lambda: "tcpcc_generated",
        )


class NftDnatLifecycleTests(unittest.TestCase):
    def test_install_is_one_exact_exclusive_atomic_batch(self) -> None:
        fixture = NftFixture()

        lease = fixture.install()

        self.assertEqual(lease.table_name, "tcpcc_case")
        self.assertFalse(lease.closed)
        self.assertEqual(
            fixture.calls,
            [(["/usr/sbin/nft", "--file", "-"], EXPECTED_BATCH)],
        )
        self.assertTrue(EXPECTED_BATCH.startswith("create table ip tcpcc_case\n"))
        self.assertNotIn("add table", EXPECTED_BATCH)
        self.assertIn("ip daddr 203.0.113.10", EXPECTED_BATCH)
        self.assertIn("tcp dport 443", EXPECTED_BATCH)
        self.assertIn("dnat to 198.18.0.2:28443", EXPECTED_BATCH)
        self.assertNotIn("flush", EXPECTED_BATCH)

    def test_generated_name_is_bounded_and_used_everywhere(self) -> None:
        fixture = NftFixture()

        lease = fixture.install(table_name=None)

        self.assertEqual(lease.table_name, "tcpcc_generated")
        self.assertEqual(len(fixture.calls), 1)
        argv, batch = fixture.calls[0]
        self.assertEqual(argv, ["/usr/sbin/nft", "--file", "-"])
        self.assertIsNotNone(batch)
        self.assertIn("create table ip tcpcc_generated\n", batch or "")
        self.assertIn("add chain ip tcpcc_generated prerouting", batch or "")
        self.assertIn("add rule ip tcpcc_generated prerouting", batch or "")

    def test_close_deletes_only_owned_table_exactly_once(self) -> None:
        fixture = NftFixture()
        lease = fixture.install()

        lease.close()
        lease.close()

        self.assertTrue(lease.closed)
        self.assertEqual(
            fixture.calls,
            [
                (["/usr/sbin/nft", "--file", "-"], EXPECTED_BATCH),
                (
                    [
                        "/usr/sbin/nft",
                        "delete",
                        "table",
                        "ip",
                        "tcpcc_case",
                    ],
                    None,
                ),
            ],
        )

    def test_rejected_create_never_registers_or_deletes_table(self) -> None:
        fixture = NftFixture()
        fixture.install_error = subprocess.CalledProcessError(
            1,
            ["/usr/sbin/nft", "--file", "-"],
            stderr="Could not process rule: File exists",
        )

        with self.assertRaises(subprocess.CalledProcessError):
            fixture.install()

        self.assertEqual(len(fixture.calls), 1)
        self.assertIsNotNone(fixture.calls[0][1])
        self.assertEqual(fixture.events, ["dnat-install"])

    def test_configuration_is_validated_before_nft_invocation(self) -> None:
        valid = {
            "listen_address": "203.0.113.10",
            "listen_port": 443,
            "target_address": "198.18.0.2",
            "target_port": 28443,
        }
        invalid = (
            {**valid, "listen_address": "not-an-ip"},
            {**valid, "listen_address": "0.0.0.0"},
            {**valid, "listen_address": "224.0.0.1"},
            {**valid, "target_address": "2001:db8::1"},
            {**valid, "listen_port": 0},
            {**valid, "listen_port": True},
            {**valid, "target_port": 65536},
            {**valid, "table_name": "Bad-Table"},
            {**valid, "table_name": "x" * 33},
            {
                "listen_address": "198.18.0.2",
                "listen_port": 443,
                "target_address": "198.18.0.2",
                "target_port": 28443,
            },
        )

        for arguments in invalid:
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    NftDnatConfig(**arguments)

        fixture = NftFixture()
        with self.assertRaises(ValueError):
            install_nft_dnat(
                NftDnatConfig(**valid),
                runner=fixture.runner,
                table_name_factory=lambda: "invalid-name",
            )
        self.assertEqual(fixture.calls, [])

    def test_default_runner_passes_argv_and_stdin_without_shell(self) -> None:
        config = NftDnatConfig(
            listen_address="203.0.113.10",
            listen_port=443,
            target_address="198.18.0.2",
            target_port=28443,
            table_name="tcpcc_case",
        )
        with mock.patch.object(tcpcc_host.subprocess, "run") as run:
            lease = install_nft_dnat(config, nft_path="/usr/sbin/nft")
            lease.close()

        self.assertEqual(run.call_count, 2)
        install_call, delete_call = run.call_args_list
        self.assertEqual(
            install_call.args,
            (["/usr/sbin/nft", "--file", "-"],),
        )
        self.assertEqual(install_call.kwargs["input"], EXPECTED_BATCH)
        self.assertNotIn("shell", install_call.kwargs)
        self.assertEqual(
            delete_call.args,
            (
                [
                    "/usr/sbin/nft",
                    "delete",
                    "table",
                    "ip",
                    "tcpcc_case",
                ],
            ),
        )
        self.assertIsNone(delete_call.kwargs["input"])
        self.assertNotIn("shell", delete_call.kwargs)

    def test_journal_removes_dnat_before_tun(self) -> None:
        fixture = NftFixture()
        journal = OwnershipJournal()
        journal.defer("tun:tcpcc0", lambda: fixture.events.append("tun-close"))
        lease = fixture.install()
        journal.defer("nft:tcpcc_case", lease.close)

        journal.close()

        self.assertEqual(
            fixture.events,
            ["dnat-install", "dnat-delete", "tun-close"],
        )

    def test_journal_reports_delete_failure_and_still_closes_tun(self) -> None:
        fixture = NftFixture()
        fixture.delete_error = OSError(errno.EIO, "injected delete failure")
        journal = OwnershipJournal()
        journal.defer("tun:tcpcc0", lambda: fixture.events.append("tun-close"))
        lease = fixture.install()
        journal.defer("nft:tcpcc_case", lease.close)

        with self.assertRaises(CleanupError) as raised:
            journal.close()

        self.assertEqual(
            fixture.events,
            ["dnat-install", "dnat-delete", "tun-close"],
        )
        self.assertEqual(
            [failure.label for failure in raised.exception.failures],
            ["nft:tcpcc_case"],
        )
        journal.close()
        self.assertEqual(fixture.events.count("dnat-delete"), 1)
        self.assertEqual(fixture.events.count("tun-close"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the composed M8.3 host-network transaction."""

from __future__ import annotations

import errno
import json
import os
import signal
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from tcpcc_host import (  # noqa: E402
    CheckResult,
    CleanupError,
    HostNetworkConfig,
    HostPreflightError,
    NftDnatConfig,
    NftDnatLease,
    NftOwnership,
    NftOwnershipObservation,
    NftOwnershipReport,
    OwnershipJournal,
    PreflightReport,
    ShutdownSignals,
    StaleOwnershipError,
    StartupRollbackError,
    TunConfig,
    TunQueue,
    acquire_host_network,
    current_nft_ownership,
    inspect_nft_ownership,
    install_nft_dnat,
)


def green_preflight() -> PreflightReport:
    return PreflightReport(
        requested_cc="cubic",
        checks=(
            CheckResult("fixture", "pass", "required", "ready", "ready", ""),
        ),
    )


def failed_preflight() -> PreflightReport:
    return PreflightReport(
        requested_cc="cubic",
        checks=(
            CheckResult(
                "fixture.required",
                "fail",
                "required",
                "missing",
                "ready",
                "fix fixture",
            ),
        ),
    )


def clean_ownership() -> NftOwnershipReport:
    return NftOwnershipReport(())


def stale_ownership() -> NftOwnershipReport:
    return NftOwnershipReport(
        (
            NftOwnershipObservation(
                table_name="tcpcc_stale",
                status="stale",
                owner_pid=999999,
                owner_start_time=123,
                tun_name="tcpcc-old0",
                detail="owner process is absent",
                remediation=(
                    "verify the recorded owner is gone, then run: "
                    "nft delete table ip tcpcc_stale"
                ),
            ),
        )
    )


def lifecycle_config() -> HostNetworkConfig:
    return HostNetworkConfig(
        requested_cc="cubic",
        tun=TunConfig(
            host_address="198.18.0.1",
            guest_address="198.18.0.2",
            name="tcpcc-unit0",
        ),
        dnat=NftDnatConfig(
            listen_address="203.0.113.10",
            listen_port=443,
            target_address="198.18.0.2",
            target_port=28443,
            table_name="tcpcc_unit",
        ),
    )


class RecordingLifecycle:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.tun_close_error: BaseException | None = None
        self.dnat_close_error: BaseException | None = None
        self.tun_error: BaseException | None = None
        self.compatibility_error: BaseException | None = None
        self.identity_error: BaseException | None = None
        self.dnat_error: BaseException | None = None

    def preflight(self, requested_cc: str) -> PreflightReport:
        self.events.append(f"preflight:{requested_cc}")
        return green_preflight()

    def ownership(self) -> NftOwnershipReport:
        self.events.append("ownership-scan")
        return clean_ownership()

    def compatibility(self, config: NftDnatConfig) -> None:
        self.events.append(
            f"compatibility:{config.listen_address}:{config.listen_port}"
        )
        if self.compatibility_error is not None:
            raise self.compatibility_error

    def tun_acquirer(self, config: TunConfig) -> TunQueue:
        self.events.append(f"tun-acquire:{config.name}")
        if self.tun_error is not None:
            raise self.tun_error

        def close(fd: int) -> None:
            self.events.append(f"tun-close:{fd}")
            if self.tun_close_error is not None:
                raise self.tun_close_error

        return TunQueue("tcpcc-unit0", 101, close)

    def identity(self, tun_name: str) -> NftOwnership:
        self.events.append(f"identity:{tun_name}")
        if self.identity_error is not None:
            raise self.identity_error
        return NftOwnership(pid=123, start_time=456, tun_name=tun_name)

    def dnat_acquirer(
        self,
        config: NftDnatConfig,
        ownership: NftOwnership,
    ) -> NftDnatLease:
        self.events.append(
            f"dnat-acquire:{config.table_name}:{ownership.marker()}"
        )
        if self.dnat_error is not None:
            raise self.dnat_error

        def runner(argv: list[str], input_text: str | None) -> None:
            self.assert_delete(argv, input_text)
            self.events.append("dnat-close:tcpcc_unit")
            if self.dnat_close_error is not None:
                raise self.dnat_close_error

        return NftDnatLease("tcpcc_unit", "/usr/sbin/nft", runner)

    @staticmethod
    def assert_delete(argv: list[str], input_text: str | None) -> None:
        if argv != [
            "/usr/sbin/nft",
            "delete",
            "table",
            "ip",
            "tcpcc_unit",
        ] or input_text is not None:
            raise AssertionError(f"unexpected delete call: {argv}, {input_text!r}")

    def acquire(self, **overrides):
        arguments = {
            "preflight_collector": self.preflight,
            "ownership_collector": self.ownership,
            "compatibility_checker": self.compatibility,
            "tun_acquirer": self.tun_acquirer,
            "dnat_acquirer": self.dnat_acquirer,
            "identity_factory": self.identity,
        }
        arguments.update(overrides)
        return acquire_host_network(lifecycle_config(), **arguments)


class FailingJournal(OwnershipJournal):
    def __init__(self, fail_at: int) -> None:
        super().__init__()
        self.fail_at = fail_at
        self.calls = 0

    def defer(self, label, callback) -> None:
        self.calls += 1
        if self.calls == self.fail_at:
            raise MemoryError(f"injected registration failure at {label}")
        super().defer(label, callback)


def proc_stat(pid: int, start_time: int, command: str = "tcpcc worker") -> str:
    fields = ["S", *(["0"] * 18), str(start_time)]
    return f"{pid} ({command}) " + " ".join(fields) + "\n"


class ComposedLifecycleTests(unittest.TestCase):
    def test_success_exposes_exact_resources_and_cleans_in_reverse(self) -> None:
        fixture = RecordingLifecycle()

        lease = fixture.acquire()

        self.assertEqual(lease.tun_name, "tcpcc-unit0")
        self.assertEqual(lease.tun_fd, 101)
        self.assertEqual(lease.table_name, "tcpcc_unit")
        self.assertTrue(lease.preflight.ok)
        self.assertFalse(lease.ownership.blocking)
        self.assertFalse(lease.closed)
        self.assertEqual(
            fixture.events[:6],
            [
                "preflight:cubic",
                "ownership-scan",
                "compatibility:203.0.113.10:443",
                "tun-acquire:tcpcc-unit0",
                "identity:tcpcc-unit0",
                (
                    "dnat-acquire:tcpcc_unit:tcpcc.owner.v1 "
                    "pid=123 start=456 tun=tcpcc-unit0"
                ),
            ],
        )

        lease.close()
        lease.close()
        self.assertTrue(lease.closed)
        self.assertEqual(
            fixture.events[-2:],
            ["dnat-close:tcpcc_unit", "tun-close:101"],
        )

    def test_preflight_and_stale_fail_before_mutation(self) -> None:
        fixture = RecordingLifecycle()
        with self.assertRaises(HostPreflightError) as raised:
            fixture.acquire(preflight_collector=lambda _cc: failed_preflight())
        self.assertIn("fixture.required", str(raised.exception))
        self.assertEqual(fixture.events, [])

        fixture = RecordingLifecycle()
        with self.assertRaises(StaleOwnershipError) as raised:
            fixture.acquire(ownership_collector=stale_ownership)
        self.assertIn("tcpcc_stale(stale)", str(raised.exception))
        self.assertEqual(
            fixture.events,
            ["preflight:cubic"],
        )

        fixture = RecordingLifecycle()
        fixture.compatibility_error = RuntimeError("unsupported nft transaction")
        with self.assertRaisesRegex(RuntimeError, "unsupported nft transaction"):
            fixture.acquire()
        self.assertEqual(
            fixture.events,
            [
                "preflight:cubic",
                "ownership-scan",
                "compatibility:203.0.113.10:443",
            ],
        )

        active = NftOwnershipReport(
            (
                NftOwnershipObservation(
                    table_name="tcpcc_active",
                    status="active",
                    owner_pid=22,
                    owner_start_time=333,
                    tun_name="tcpcc-live0",
                    detail="owner pid and process start time match",
                    remediation="",
                ),
            )
        )
        fixture = RecordingLifecycle()
        lease = fixture.acquire(ownership_collector=lambda: active)
        lease.close()
        self.assertIn("tun-acquire:tcpcc-unit0", fixture.events)

    def test_each_late_startup_failure_rolls_back_tun(self) -> None:
        for boundary in ("identity", "dnat"):
            with self.subTest(boundary=boundary):
                fixture = RecordingLifecycle()
                injected = OSError(errno.EIO, f"{boundary} failed")
                if boundary == "identity":
                    fixture.identity_error = injected
                else:
                    fixture.dnat_error = injected

                with self.assertRaises(OSError) as raised:
                    fixture.acquire()

                self.assertIs(raised.exception, injected)
                self.assertEqual(fixture.events[-1], "tun-close:101")
                self.assertNotIn("dnat-close:tcpcc_unit", fixture.events)

    def test_tun_failure_has_no_later_acquisition_or_cleanup(self) -> None:
        fixture = RecordingLifecycle()
        fixture.tun_error = OSError(errno.EPERM, "TUN denied")

        with self.assertRaises(OSError):
            fixture.acquire()

        self.assertEqual(
            fixture.events,
            [
                "preflight:cubic",
                "ownership-scan",
                "compatibility:203.0.113.10:443",
                "tun-acquire:tcpcc-unit0",
            ],
        )

    def test_registration_failures_close_unregistered_resource(self) -> None:
        fixture = RecordingLifecycle()
        first = FailingJournal(1)
        with self.assertRaises(MemoryError):
            fixture.acquire(journal_factory=lambda: first)
        self.assertEqual(fixture.events[-1], "tun-close:101")

        fixture = RecordingLifecycle()
        second = FailingJournal(2)
        with self.assertRaises(MemoryError):
            fixture.acquire(journal_factory=lambda: second)
        self.assertEqual(
            fixture.events[-2:],
            ["dnat-close:tcpcc_unit", "tun-close:101"],
        )

    def test_startup_error_preserves_every_rollback_failure(self) -> None:
        fixture = RecordingLifecycle()
        fixture.dnat_error = OSError(errno.EINVAL, "DNAT rejected")
        fixture.tun_close_error = OSError(errno.EIO, "TUN close failed")

        with self.assertRaises(StartupRollbackError) as raised:
            fixture.acquire()

        self.assertIs(raised.exception.startup_error, fixture.dnat_error)
        self.assertEqual(
            [item.label for item in raised.exception.cleanup_error.failures],
            ["tun:tcpcc-unit0"],
        )
        self.assertIn("DNAT rejected", str(raised.exception))
        self.assertIn("TUN close failed", str(raised.exception))

    def test_orderly_close_aggregates_dnat_and_tun_failures(self) -> None:
        fixture = RecordingLifecycle()
        fixture.dnat_close_error = OSError(errno.EIO, "DNAT delete failed")
        fixture.tun_close_error = OSError(errno.EBADF, "TUN close failed")
        lease = fixture.acquire()

        with self.assertRaises(CleanupError) as raised:
            lease.close()

        self.assertEqual(
            [item.label for item in raised.exception.failures],
            ["nft:tcpcc_unit", "tun:tcpcc-unit0"],
        )
        self.assertEqual(
            fixture.events[-2:],
            ["dnat-close:tcpcc_unit", "tun-close:101"],
        )
        lease.close()

    def test_config_requires_dnat_target_to_match_tun_guest(self) -> None:
        with self.assertRaises(ValueError):
            HostNetworkConfig(
                requested_cc="cubic",
                tun=TunConfig("198.18.0.1", "198.18.0.2"),
                dnat=NftDnatConfig(
                    "203.0.113.10",
                    443,
                    "198.18.0.3",
                    28443,
                ),
            )

    def test_ownership_scan_classifies_without_touching_unmarked_tables(self) -> None:
        tables = {
            "nftables": [
                {"metainfo": {"json_schema_version": 1}},
                {
                    "rule": {
                        "family": "ip",
                        "table": "tcpcc_active",
                        "chain": "prerouting",
                        "comment": (
                            "tcpcc.owner.v1 pid=10 start=100 tun=tcpcc-a0"
                        ),
                    }
                },
                {
                    "rule": {
                        "family": "ip",
                        "table": "tcpcc_absent",
                        "chain": "prerouting",
                        "comment": (
                            "tcpcc.owner.v1 pid=11 start=110 tun=tcpcc-b0"
                        ),
                    }
                },
                {
                    "rule": {
                        "family": "ip",
                        "table": "tcpcc_reused",
                        "chain": "prerouting",
                        "comment": (
                            "tcpcc.owner.v1 pid=12 start=120 tun=tcpcc-c0"
                        ),
                    }
                },
                {
                    "rule": {
                        "family": "ip",
                        "table": "tcpcc_bad",
                        "chain": "prerouting",
                        "comment": "tcpcc.owner.v2 unsupported",
                    }
                },
                {
                    "rule": {
                        "family": "ip",
                        "table": "tcpcc_unmarked",
                        "chain": "prerouting",
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "ignored_family",
                        "chain": "prerouting",
                        "comment": (
                            "tcpcc.owner.v1 pid=10 start=100 tun=tcpcc-a0"
                        ),
                    }
                },
            ]
        }
        calls: list[list[str]] = []

        def runner(argv: list[str]) -> str:
            calls.append(list(argv))
            return json.dumps(tables)

        def reader(path: Path) -> str:
            pid = int(path.parent.name)
            if pid == 10:
                return proc_stat(pid, 100, "name with ) characters")
            if pid == 12:
                return proc_stat(pid, 121)
            raise FileNotFoundError(path)

        report = inspect_nft_ownership(
            nft_path="/usr/sbin/nft",
            runner=runner,
            proc_root=Path("/fixture/proc"),
            reader=reader,
        )

        self.assertEqual(
            calls,
            [["/usr/sbin/nft", "--json", "list", "ruleset", "ip"]],
        )
        self.assertTrue(report.blocking)
        self.assertEqual(
            [(item.table_name, item.status) for item in report.observations],
            [
                ("tcpcc_absent", "stale"),
                ("tcpcc_active", "active"),
                ("tcpcc_bad", "malformed"),
                ("tcpcc_reused", "stale"),
            ],
        )
        absent = report.observations[0]
        self.assertIn(
            "nft delete table ip tcpcc_absent",
            absent.remediation,
        )
        self.assertNotIn("tcpcc_unmarked", report.to_json())

    def test_owned_table_batch_contains_versioned_process_identity(self) -> None:
        calls: list[tuple[list[str], str | None]] = []

        def runner(argv: list[str], input_text: str | None) -> None:
            calls.append((list(argv), input_text))

        owner = NftOwnership(pid=123, start_time=456, tun_name="tcpcc-unit0")
        lease = install_nft_dnat(
            lifecycle_config().dnat,
            runner=runner,
            ownership=owner,
        )

        self.assertIn(
            (
                "add rule ip tcpcc_unit prerouting ip daddr 203.0.113.10 "
                "tcp dport 443 counter dnat to 198.18.0.2:28443 comment "
                '"tcpcc.owner.v1 pid=123 start=456 tun=tcpcc-unit0"\n'
            ),
            calls[0][1] or "",
        )
        lease.close()

    def test_current_identity_parses_proc_stat_and_rejects_bad_values(self) -> None:
        owner = current_nft_ownership(
            "tcpcc-unit0",
            proc_root=Path("/fixture/proc"),
            reader=lambda _path: proc_stat(77, 9876, "strange ) name"),
            pid_provider=lambda: 77,
        )
        self.assertEqual(owner.marker(), (
            "tcpcc.owner.v1 pid=77 start=9876 tun=tcpcc-unit0"
        ))
        with self.assertRaises(ValueError):
            NftOwnership(pid=0, start_time=1, tun_name="tcpcc-unit0")

    def test_shutdown_signal_requests_once_and_restores_handler(self) -> None:
        previous = signal.getsignal(signal.SIGUSR1)
        shutdown = ShutdownSignals((signal.SIGUSR1,))

        with shutdown:
            installed = signal.getsignal(signal.SIGUSR1)
            self.assertNotEqual(installed, previous)
            os.kill(os.getpid(), signal.SIGUSR1)
            self.assertTrue(shutdown.wait(1.0))
            self.assertTrue(shutdown.requested)
            self.assertEqual(shutdown.requested_signal, signal.SIGUSR1)
            shutdown.request(signal.SIGTERM)
            self.assertEqual(shutdown.requested_signal, signal.SIGUSR1)

        self.assertEqual(signal.getsignal(signal.SIGUSR1), previous)
        shutdown.restore()
        with self.assertRaises(ValueError):
            ShutdownSignals((signal.SIGUSR1, signal.SIGUSR1))


if __name__ == "__main__":
    unittest.main(verbosity=2)

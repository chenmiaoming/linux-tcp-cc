#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Unit and privileged integration tests for the M8.3 TUN lifecycle."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import secrets
import struct
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from tcpcc_host import (  # noqa: E402
    CleanupError,
    IFF_NO_PI,
    IFF_TUN,
    IFF_TUN_EXCL,
    IFREQ_SIZE,
    OwnershipJournal,
    TUNSETIFF,
    TUN_IFF_FLAGS,
    TunConfig,
    create_tun_queue,
)


class TunFixture:
    def __init__(self) -> None:
        self.next_fd = 100
        self.opens: list[tuple[str, int, int]] = []
        self.ioctls: list[tuple[int, int, str, int, int, bool]] = []
        self.commands: list[list[str]] = []
        self.closed: list[int] = []
        self.ioctl_errors: dict[str, OSError] = {}
        self.kernel_names: dict[str, str] = {}
        self.fail_command: int | None = None
        self.command_error: BaseException | None = None
        self.close_error: OSError | None = None

    def opener(self, path: str, flags: int) -> int:
        fd = self.next_fd
        self.next_fd += 1
        self.opens.append((path, flags, fd))
        return fd

    def ioctl(
        self,
        fd: int,
        request: int,
        ifreq: bytearray,
        mutate: bool,
    ) -> int:
        encoded_name, flags = struct.unpack_from("16sH", ifreq)
        name = encoded_name.split(b"\0", 1)[0].decode("ascii")
        self.ioctls.append(
            (fd, request, name, flags, len(ifreq), mutate)
        )
        error = self.ioctl_errors.get(name)
        if error is not None:
            raise error
        actual = self.kernel_names.get(name, name)
        struct.pack_into("16s", ifreq, 0, actual.encode("ascii"))
        return 0

    def runner(self, argv: list[str]) -> None:
        self.commands.append(list(argv))
        if self.command_error is not None:
            raise self.command_error
        if self.fail_command == len(self.commands):
            raise subprocess.CalledProcessError(
                2,
                argv,
                stderr="injected ip failure",
            )

    def closer(self, fd: int) -> None:
        self.closed.append(fd)
        if self.close_error is not None:
            raise self.close_error

    def create(
        self,
        *,
        name: str | None = "tcpcc-test0",
        host_address: str = "198.18.0.1",
        guest_address: str = "198.18.0.2",
        name_factory=lambda: "tcpcc-auto0",
        max_name_attempts: int = 8,
    ):
        return create_tun_queue(
            TunConfig(
                host_address=host_address,
                guest_address=guest_address,
                mtu=1460,
                name=name,
            ),
            tun_path=Path("/fixture/dev/net/tun"),
            ip_path="/usr/sbin/ip",
            opener=self.opener,
            ioctl=self.ioctl,
            closer=self.closer,
            runner=self.runner,
            name_factory=name_factory,
            max_name_attempts=max_name_attempts,
        )


class TunLifecycleTests(unittest.TestCase):
    def test_create_uses_one_exclusive_nonpersistent_tun_queue(self) -> None:
        fixture = TunFixture()
        queue = fixture.create()

        self.assertEqual(queue.name, "tcpcc-test0")
        self.assertEqual(queue.fd, 100)
        self.assertEqual(queue.fileno(), 100)
        self.assertFalse(queue.closed)
        self.assertEqual(
            fixture.opens,
            [
                (
                    "/fixture/dev/net/tun",
                    os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC,
                    100,
                )
            ],
        )
        self.assertEqual(
            fixture.ioctls,
            [
                (
                    100,
                    TUNSETIFF,
                    "tcpcc-test0",
                    IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL,
                    IFREQ_SIZE,
                    True,
                )
            ],
        )
        self.assertEqual(TUN_IFF_FLAGS, IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL)
        self.assertEqual(
            fixture.commands,
            [
                [
                    "/usr/sbin/ip",
                    "address",
                    "add",
                    "198.18.0.1/32",
                    "peer",
                    "198.18.0.2/32",
                    "dev",
                    "tcpcc-test0",
                ],
                [
                    "/usr/sbin/ip",
                    "link",
                    "set",
                    "dev",
                    "tcpcc-test0",
                    "mtu",
                    "1460",
                    "up",
                ],
            ],
        )
        self.assertEqual(fixture.closed, [])

        queue.close()
        queue.close()
        self.assertTrue(queue.closed)
        self.assertEqual(fixture.closed, [100])
        with self.assertRaisesRegex(ValueError, "closed"):
            _ = queue.fd

    def test_ipv6_create_installs_explicit_guest_route(self) -> None:
        fixture = TunFixture()
        queue = fixture.create(
            host_address="fd00:198:18::1",
            guest_address="fd00:198:18::2",
        )

        self.assertEqual(
            fixture.commands,
            [
                [
                    "/usr/sbin/ip",
                    "address",
                    "add",
                    "fd00:198:18::1/128",
                    "peer",
                    "fd00:198:18::2/128",
                    "dev",
                    "tcpcc-test0",
                ],
                [
                    "/usr/sbin/ip",
                    "link",
                    "set",
                    "dev",
                    "tcpcc-test0",
                    "mtu",
                    "1460",
                    "up",
                ],
                [
                    "/usr/sbin/ip",
                    "-6",
                    "route",
                    "replace",
                    "fd00:198:18::2/128",
                    "dev",
                    "tcpcc-test0",
                    "src",
                    "fd00:198:18::1",
                ],
            ],
        )
        queue.close()

    def test_each_setup_failure_closes_the_new_fd(self) -> None:
        fixture = TunFixture()
        fixture.ioctl_errors["tcpcc-test0"] = OSError(
            errno.EINVAL,
            "injected ioctl failure",
        )
        with self.assertRaises(OSError):
            fixture.create()
        self.assertEqual(fixture.closed, [100])
        self.assertEqual(fixture.commands, [])

        for fail_command in (1, 2):
            with self.subTest(fail_command=fail_command):
                fixture = TunFixture()
                fixture.fail_command = fail_command
                with self.assertRaises(subprocess.CalledProcessError):
                    fixture.create()
                self.assertEqual(fixture.closed, [100])
                self.assertEqual(len(fixture.commands), fail_command)

        fixture = TunFixture()
        fixture.fail_command = 3
        with self.assertRaises(subprocess.CalledProcessError):
            fixture.create(
                host_address="fd00:198:18::1",
                guest_address="fd00:198:18::2",
            )
        self.assertEqual(fixture.closed, [100])
        self.assertEqual(len(fixture.commands), 3)

    def test_kernel_name_mismatch_closes_fd_before_reporting(self) -> None:
        fixture = TunFixture()
        fixture.kernel_names["tcpcc-test0"] = "unexpected0"

        with self.assertRaisesRegex(RuntimeError, "unexpected0"):
            fixture.create()

        self.assertEqual(fixture.closed, [100])
        self.assertEqual(fixture.commands, [])

    def test_requested_existing_name_is_never_adopted_or_retried(self) -> None:
        fixture = TunFixture()
        fixture.ioctl_errors["tcpcc-owned"] = OSError(
            errno.EBUSY,
            "already exists",
        )

        with self.assertRaises(OSError) as raised:
            fixture.create(name="tcpcc-owned")

        self.assertEqual(raised.exception.errno, errno.EBUSY)
        self.assertEqual(len(fixture.opens), 1)
        self.assertEqual(fixture.closed, [100])
        self.assertEqual(fixture.commands, [])

    def test_generated_name_retries_only_a_kernel_collision(self) -> None:
        fixture = TunFixture()
        names = iter(("tcpcc-old0", "tcpcc-new0"))
        fixture.ioctl_errors["tcpcc-old0"] = OSError(
            errno.EBUSY,
            "collision",
        )

        queue = fixture.create(name=None, name_factory=lambda: next(names))

        self.assertEqual(queue.name, "tcpcc-new0")
        self.assertEqual([call[2] for call in fixture.ioctls], [
            "tcpcc-old0",
            "tcpcc-new0",
        ])
        self.assertEqual(fixture.closed, [100])
        queue.close()
        self.assertEqual(fixture.closed, [100, 101])

    def test_generated_name_does_not_retry_other_errors(self) -> None:
        fixture = TunFixture()
        names = iter(("tcpcc-bad0", "tcpcc-unused"))
        fixture.ioctl_errors["tcpcc-bad0"] = OSError(
            errno.EPERM,
            "not permitted",
        )

        with self.assertRaises(OSError) as raised:
            fixture.create(name=None, name_factory=lambda: next(names))

        self.assertEqual(raised.exception.errno, errno.EPERM)
        self.assertEqual(len(fixture.opens), 1)
        self.assertEqual(fixture.closed, [100])

        fixture = TunFixture()
        fixture.command_error = OSError(errno.EBUSY, "ip executable busy")
        names = iter(("tcpcc-new0", "tcpcc-unused"))
        with self.assertRaises(OSError) as raised:
            fixture.create(name=None, name_factory=lambda: next(names))
        self.assertEqual(raised.exception.errno, errno.EBUSY)
        self.assertEqual(len(fixture.opens), 1)
        self.assertEqual(fixture.closed, [100])

    def test_generated_name_collision_budget_is_bounded(self) -> None:
        fixture = TunFixture()
        fixture.ioctl_errors.update(
            {
                "tcpcc-old0": OSError(errno.EBUSY, "collision"),
                "tcpcc-old1": OSError(errno.EEXIST, "collision"),
            }
        )
        names = iter(("tcpcc-old0", "tcpcc-old1"))

        with self.assertRaises(FileExistsError) as raised:
            fixture.create(
                name=None,
                name_factory=lambda: next(names),
                max_name_attempts=2,
            )

        self.assertEqual(raised.exception.errno, errno.EEXIST)
        self.assertEqual(fixture.closed, [100, 101])

    def test_configuration_is_validated_before_open(self) -> None:
        invalid_configs = (
            {"host_address": "not-an-ip", "guest_address": "198.18.0.2"},
            {"host_address": 1, "guest_address": "198.18.0.2"},
            {"host_address": "2001:db8::1", "guest_address": "198.18.0.2"},
            {"host_address": "198.18.0.1", "guest_address": "198.18.0.1"},
            {
                "host_address": "198.18.0.1",
                "guest_address": "198.18.0.2",
                "mtu": 67,
            },
            {
                "host_address": "198.18.0.1",
                "guest_address": "198.18.0.2",
                "mtu": True,
            },
            {
                "host_address": "198.18.0.1",
                "guest_address": "198.18.0.2",
                "name": "bad/name",
            },
            {
                "host_address": "198.18.0.1",
                "guest_address": "198.18.0.2",
                "name": "x" * 16,
            },
        )

        for arguments in invalid_configs:
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    TunConfig(**arguments)

    def test_ownership_journal_reverses_and_aggregates_cleanup(self) -> None:
        journal = OwnershipJournal()
        called: list[str] = []

        def cleanup(label: str, fail: bool = False):
            def callback() -> None:
                called.append(label)
                if fail:
                    raise OSError(errno.EIO, f"{label} failed")

            return callback

        journal.defer("tun", cleanup("tun", fail=True))
        journal.defer("route", cleanup("route"))
        journal.defer("firewall", cleanup("firewall", fail=True))

        with self.assertRaises(CleanupError) as raised:
            journal.close()

        self.assertTrue(journal.closed)
        self.assertEqual(called, ["firewall", "route", "tun"])
        self.assertEqual(
            [failure.label for failure in raised.exception.failures],
            ["firewall", "tun"],
        )
        self.assertIn("firewall", str(raised.exception))
        self.assertIn("tun", str(raised.exception))

        journal.close()
        self.assertEqual(called, ["firewall", "route", "tun"])
        with self.assertRaises(RuntimeError):
            journal.defer("late", lambda: None)


def _ip(
    argv: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["ip", *argv],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _assert_link_disappears(name: str) -> None:
    for _ in range(50):
        if _ip(["link", "show", "dev", name], check=False).returncode != 0:
            return
        time.sleep(0.02)
    raise AssertionError(f"nonpersistent TUN {name} survived queue close")


def run_privileged_integration() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("privileged TUN integration must run as root")
    if not Path("/dev/net/tun").is_char_device():
        raise RuntimeError("/dev/net/tun is not an available character device")

    rollback_name = f"tcpccf{secrets.token_hex(4)}"

    def reject_configuration(argv: list[str]) -> None:
        raise subprocess.CalledProcessError(
            2,
            argv,
            stderr="injected integration failure",
        )

    try:
        create_tun_queue(
            TunConfig(
                host_address="198.18.253.1",
                guest_address="198.18.253.2",
                name=rollback_name,
            ),
            runner=reject_configuration,
        )
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError("injected iproute2 failure unexpectedly succeeded")
    _assert_link_disappears(rollback_name)

    journal = OwnershipJournal()
    queue = create_tun_queue(
        TunConfig(
            host_address="198.18.254.1",
            guest_address="198.18.254.2",
            mtu=1460,
        )
    )
    journal.defer(f"tun:{queue.name}", queue.close)
    name = queue.name
    details = ""
    collision_rejected = False
    try:
        if not fcntl.fcntl(queue.fd, fcntl.F_GETFL) & os.O_NONBLOCK:
            raise AssertionError("TUN queue fd is not nonblocking")
        if os.get_inheritable(queue.fd):
            raise AssertionError("TUN queue fd is unexpectedly inheritable")
        details = _ip(["-details", "address", "show", "dev", name]).stdout
        expected_fragments = (
            "POINTOPOINT",
            "UP",
            "mtu 1460",
            "198.18.254.1 peer 198.18.254.2/32",
        )
        for fragment in expected_fragments:
            if fragment not in details:
                raise AssertionError(
                    f"missing {fragment!r} in ip output for {name}: {details}"
                )

        try:
            create_tun_queue(
                TunConfig(
                    host_address="198.18.252.1",
                    guest_address="198.18.252.2",
                    name=name,
                )
            )
        except OSError as error:
            if error.errno not in {errno.EBUSY, errno.EEXIST}:
                raise
            collision_rejected = True
        else:
            raise AssertionError(f"existing TUN {name} was unexpectedly adopted")
        if _ip(["link", "show", "dev", name], check=False).returncode != 0:
            raise AssertionError(f"collision attempt removed owned TUN {name}")
    finally:
        journal.close()

    _assert_link_disappears(name)

    print(
        json.dumps(
            {
                "schema": "tcpcc.tun-integration.v1",
                "interface": name,
                "existed_while_fd_open": True,
                "existing_name_rejected": collision_rejected,
                "failure_rolled_back": True,
                "removed_after_fd_close": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    if sys.argv[1:] == ["--integration"]:
        run_privileged_integration()
    else:
        unittest.main(verbosity=2)

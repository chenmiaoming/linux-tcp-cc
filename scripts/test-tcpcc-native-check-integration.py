#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Privileged regression for read-only native host qualification."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_ADDRESS = "203.0.113.10"
PUBLIC_PORTS = (18654, 18655)
BACKEND_PORTS = (18664, 18665)
TIMEOUT = 20.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--integration", action="store_true")
    parser.add_argument(
        "--firewall-backend",
        choices=("nft-lib", "nft-exec", "iptables"),
    )
    parser.add_argument(
        "--iptables-variant",
        choices=("iptables", "iptables-nft", "iptables-legacy"),
        default="iptables",
    )
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--output-dir", type=Path)
    return parser.parse_args()


def run(
    command: list[str],
    *,
    check: bool = True,
    timeout: float = TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed with {completed.returncode}: {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def ns_command(namespace: str, *command: str) -> list[str]:
    return ["ip", "netns", "exec", namespace, *command]


def selected_save_command(variant: str) -> str:
    return f"{variant}-save"


def firewall_snapshot(namespace: str, backend: str, variant: str) -> str:
    if backend in {"nft-lib", "nft-exec"}:
        return run(ns_command(namespace, "nft", "list", "ruleset", "ip")).stdout
    return run(
        ns_command(namespace, selected_save_command(variant), "-t", "nat")
    ).stdout


def assert_tun_absent(namespace: str, tun_name: str) -> None:
    result = run(
        ns_command(namespace, "ip", "link", "show", "dev", tun_name),
        check=False,
    )
    if result.returncode == 0:
        raise RuntimeError(f"read-only boundary created unexpected TUN {tun_name}")


def install_stale_marker(
    namespace: str,
    backend: str,
    variant: str,
    resource: str,
    marker: str,
) -> None:
    if backend in {"nft-lib", "nft-exec"}:
        run(ns_command(namespace, "nft", "add", "table", "ip", resource))
        run(ns_command(namespace, "nft", "add", "chain", "ip", resource, "probe"))
        run(
            ns_command(
                namespace,
                "nft",
                "add",
                "rule",
                "ip",
                resource,
                "probe",
                "counter",
                "comment",
                f'"{marker}"',
            )
        )
        return

    run(
        ns_command(
            namespace,
            variant,
            "--wait",
            "-t",
            "nat",
            "-N",
            resource,
        )
    )
    run(
        ns_command(
            namespace,
            variant,
            "--wait",
            "-t",
            "nat",
            "-A",
            resource,
            "-m",
            "comment",
            "--comment",
            marker,
            "-j",
            "RETURN",
        )
    )


def remove_stale_marker(
    namespace: str,
    backend: str,
    variant: str,
    resource: str,
) -> None:
    if backend in {"nft-lib", "nft-exec"}:
        run(
            ns_command(namespace, "nft", "delete", "table", "ip", resource),
            check=False,
        )
        return
    run(
        ns_command(
            namespace,
            variant,
            "--wait",
            "-t",
            "nat",
            "-F",
            resource,
        ),
        check=False,
    )
    run(
        ns_command(
            namespace,
            variant,
            "--wait",
            "-t",
            "nat",
            "-X",
            resource,
        ),
        check=False,
    )


def tcpcc_command(
    namespace: str,
    kernel: Path,
    backend: str,
    variant: str,
    tun_name: str,
) -> list[str]:
    command = ns_command(
        namespace,
        str(ROOT / "tcpcc"),
        "--forward",
        f"{PUBLIC_ADDRESS}:{PUBLIC_PORTS[0]}=127.0.0.1:{BACKEND_PORTS[0]}",
        "--forward",
        f"{PUBLIC_ADDRESS}:{PUBLIC_PORTS[1]}=127.0.0.1:{BACKEND_PORTS[1]}",
        "--cc",
        "bbr",
        "--kernel",
        str(kernel),
        "--firewall-backend",
        backend,
        "--tun-name",
        tun_name,
    )
    if backend == "iptables":
        command.extend(("--iptables-variant", variant))
    return command


def publish_artifacts(output_dir: Path | None, sources: tuple[Path, ...]) -> None:
    if output_dir is None:
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    for source in sources:
        if source.exists():
            shutil.copy2(source, output_dir / source.name)


def integration(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise PermissionError("--integration requires root")
    if args.firewall_backend is None or args.kernel is None:
        raise ValueError("--integration requires --firewall-backend and --kernel")
    kernel = args.kernel.resolve(strict=True)
    if not os.access(kernel, os.X_OK):
        raise PermissionError(f"kernel image is not executable: {kernel}")

    suffix = secrets.token_hex(3)
    namespace = f"tcpcc-ck-{suffix}"
    tun_name = f"tcpck{suffix}"
    stale_resource = (
        f"tcpcc_stale_{suffix}"
        if args.firewall_backend in {"nft-lib", "nft-exec"}
        else f"TCPCC_STALE_{suffix}"
    )
    stale_marker = "tcpcc.owner.v1 pid=999999 start=1 tun=tcpccdead"
    created_namespace = False
    stale_installed = False

    with tempfile.TemporaryDirectory(prefix="tcpcc-native-check-") as temporary:
        temp = Path(temporary)
        success_log = temp / "check-success.json"
        success_err = temp / "check-success.stderr"
        stale_log = temp / "stale-start.stdout"
        stale_err = temp / "stale-start.stderr"
        try:
            run(["ip", "netns", "add", namespace])
            created_namespace = True
            run(["ip", "-n", namespace, "link", "set", "lo", "up"])
            run(ns_command(namespace, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"))

            before = firewall_snapshot(
                namespace, args.firewall_backend, args.iptables_variant
            )
            command = tcpcc_command(
                namespace,
                kernel,
                args.firewall_backend,
                args.iptables_variant,
                tun_name,
            )
            checked = run(command[:5] + ["--check"] + command[5:])
            success_log.write_text(checked.stdout, encoding="utf-8")
            success_err.write_text(checked.stderr, encoding="utf-8")
            lines = [line for line in checked.stdout.splitlines() if line.strip()]
            if len(lines) != 1:
                raise RuntimeError(f"check emitted unexpected stdout: {checked.stdout!r}")
            document = json.loads(lines[0])
            expected = {
                "address_family": "ipv4",
                "event": "check",
                "firewall_backend": args.firewall_backend,
                "forward_count": 2,
                "ok": True,
                "schema": "tcpcc.check.v1",
            }
            if document != expected:
                raise RuntimeError(
                    f"check success contract mismatch: {document!r}, expected {expected!r}"
                )
            assert_tun_absent(namespace, tun_name)
            after = firewall_snapshot(
                namespace, args.firewall_backend, args.iptables_variant
            )
            if after != before:
                raise RuntimeError("--check changed firewall state")

            install_stale_marker(
                namespace,
                args.firewall_backend,
                args.iptables_variant,
                stale_resource,
                stale_marker,
            )
            stale_installed = True
            stale_before = firewall_snapshot(
                namespace, args.firewall_backend, args.iptables_variant
            )
            rejected = run(command, check=False)
            stale_log.write_text(rejected.stdout, encoding="utf-8")
            stale_err.write_text(rejected.stderr, encoding="utf-8")
            if rejected.returncode == 0:
                raise RuntimeError("normal startup accepted a stale ownership marker")
            if "stale tcpcc firewall resource blocks startup" not in rejected.stderr:
                raise RuntimeError(
                    f"stale ownership diagnostic missing: {rejected.stderr!r}"
                )
            assert_tun_absent(namespace, tun_name)
            stale_after = firewall_snapshot(
                namespace, args.firewall_backend, args.iptables_variant
            )
            if stale_after != stale_before:
                raise RuntimeError("stale ownership rejection changed firewall state")

            print(
                "native-check: "
                f"backend={args.firewall_backend} read_only=proved "
                "stale_before_tun=proved"
            )
            return 0
        finally:
            if stale_installed:
                remove_stale_marker(
                    namespace,
                    args.firewall_backend,
                    args.iptables_variant,
                    stale_resource,
                )
            publish_artifacts(
                args.output_dir,
                (success_log, success_err, stale_log, stale_err),
            )
            if created_namespace:
                run(["ip", "netns", "delete", namespace], check=False)


def main() -> int:
    args = parse_args()
    if not args.integration:
        raise ValueError("refusing privileged setup without --integration")
    return integration(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"native check integration failed: {error}", file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Privileged failure, signal, and stale-resource tests for all firewalls."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import selectors
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from tcpcc_host import (  # noqa: E402
    CheckResult,
    HostNetworkConfig,
    NftDnatConfig,
    PreflightReport,
    ShutdownSignals,
    StaleOwnershipError,
    TunConfig,
    acquire_host_network,
    create_firewall_backend,
    create_tun_queue,
)

LISTEN_ADDRESS = "203.0.113.10"
LISTEN_PORT = 18443
TUN_HOST = "198.19.0.1"
TUN_GUEST = "198.19.0.2"
TARGET_PORT = 28443
STALE_TABLE = "tcpcc_stale_ci"
STALE_CHAIN = "TCPCC_deadbeef0001"
STALE_TUN = "tcpcc-stale0"
FAIL_TABLE = "tcpcc_fail_ci"
TIMEOUT = 20.0
BACKENDS = ("nft-lib", "nft-exec", "iptables")
IPTABLES_VARIANTS = ("iptables", "iptables-nft", "iptables-legacy")


def _run(
    argv: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        input=input_text,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=TIMEOUT,
    )


def _green_preflight(_requested_cc: str) -> PreflightReport:
    return PreflightReport(
        requested_cc="cubic",
        checks=(
            CheckResult("fixture", "pass", "required", "ready", "ready", ""),
        ),
    )


def _firewall(backend: str, iptables_variant: str):
    if backend == "iptables":
        return create_firewall_backend(
            backend,
            iptables_path=iptables_variant,
            iptables_restore_path=f"{iptables_variant}-restore",
            iptables_save_path=f"{iptables_variant}-save",
        )
    return create_firewall_backend(backend)


def _config(
    backend: str,
    *,
    tun_name: str | None = None,
) -> HostNetworkConfig:
    return HostNetworkConfig(
        requested_cc="cubic",
        tun=TunConfig(
            host_address=TUN_HOST,
            guest_address=TUN_GUEST,
            name=tun_name,
        ),
        dnat=NftDnatConfig(
            listen_address=LISTEN_ADDRESS,
            listen_port=LISTEN_PORT,
            target_address=TUN_GUEST,
            target_port=TARGET_PORT,
        ),
        firewall_backend=backend,
    )


def _create_failure_resource(backend: str, iptables_variant: str) -> None:
    if backend.startswith("nft-"):
        _run(["nft", "create", "table", "ip", FAIL_TABLE])
    else:
        _run(
            [
                iptables_variant,
                "--wait",
                "-t",
                "nat",
                "-N",
                FAIL_TABLE,
            ]
        )


def _read_failure_resource(backend: str, iptables_variant: str) -> str:
    if backend.startswith("nft-"):
        argv = ["nft", "list", "table", "ip", FAIL_TABLE]
    else:
        argv = [iptables_variant, "--wait", "-t", "nat", "-S", FAIL_TABLE]
    return _run(argv).stdout


def _delete_failure_resource(backend: str, iptables_variant: str) -> None:
    if backend.startswith("nft-"):
        argv = ["nft", "delete", "table", "ip", FAIL_TABLE]
    else:
        argv = [iptables_variant, "--wait", "-t", "nat", "-X", FAIL_TABLE]
    _run(argv)


def run_install_failure_probe(backend: str, iptables_variant: str) -> None:
    acquired = {}
    firewall = _firewall(backend, iptables_variant)
    _create_failure_resource(backend, iptables_variant)
    resource_before = _read_failure_resource(backend, iptables_variant)

    def acquire_tun(config: TunConfig):
        queue = create_tun_queue(config)
        acquired["queue"] = queue
        return queue

    def reject_dnat(config: NftDnatConfig, ownership):
        return firewall.install(
            NftDnatConfig(
                listen_address=config.listen_address,
                listen_port=config.listen_port,
                target_address=config.target_address,
                target_port=config.target_port,
                table_name=FAIL_TABLE,
            ),
            ownership,
        )

    try:
        acquire_host_network(
            _config(backend, tun_name="tcpcc-fail0"),
            firewall=firewall,
            preflight_collector=_green_preflight,
            compatibility_checker=lambda _config: None,
            tun_acquirer=acquire_tun,
            dnat_acquirer=reject_dnat,
        )
    except (subprocess.CalledProcessError, RuntimeError):
        pass
    else:
        raise AssertionError("injected firewall failure unexpectedly succeeded")

    queue = acquired["queue"]
    link = _run(
        ["ip", "link", "show", "dev", queue.name],
        check=False,
    )
    if not queue.closed or link.returncode == 0:
        raise AssertionError("TUN survived failed DNAT acquisition")
    resource_after = _read_failure_resource(backend, iptables_variant)
    if resource_after != resource_before:
        raise AssertionError("rejected DNAT transaction changed existing table")
    _delete_failure_resource(backend, iptables_variant)
    print(
        json.dumps(
            {
                "backend": backend,
                "dnat_failure_reported": True,
                "existing_resource_unchanged": True,
                "tun_removed": True,
                "tun": queue.name,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def run_signal_worker(backend: str, iptables_variant: str) -> None:
    lease = None
    firewall = _firewall(backend, iptables_variant)
    with ShutdownSignals() as shutdown:
        lease = acquire_host_network(
            _config(backend),
            firewall=firewall,
            preflight_collector=_green_preflight,
        )
        try:
            print(
                json.dumps(
                    {
                        "status": "ready",
                        "pid": os.getpid(),
                        "tun": lease.tun_name,
                        "backend": lease.firewall_backend,
                        "resource": lease.firewall_resource,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                flush=True,
            )
            if not shutdown.wait(TIMEOUT):
                raise TimeoutError("signal worker received no shutdown request")
        finally:
            lease.close()
    print(
        json.dumps(
            {
                "status": "closed",
                "signal": shutdown.requested_signal,
                "resources_removed": lease.closed,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )


def run_stale_probe(backend: str, iptables_variant: str) -> None:
    firewall = _firewall(backend, iptables_variant)
    report = firewall.inspect_ownership()
    called = False

    def forbidden_tun(_config: TunConfig):
        nonlocal called
        called = True
        raise AssertionError("stale ownership allowed TUN acquisition")

    try:
        acquire_host_network(
            _config(backend, tun_name=STALE_TUN),
            firewall=firewall,
            preflight_collector=_green_preflight,
            tun_acquirer=forbidden_tun,
        )
    except StaleOwnershipError as error:
        if error.report != report:
            raise AssertionError("startup stale report changed between reads")
    else:
        raise AssertionError("stale ownership unexpectedly allowed startup")
    if called:
        raise AssertionError("TUN acquirer ran after stale ownership report")
    print(
        json.dumps(
            {
                "blocked_before_tun": True,
                "report": report.as_dict(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def run_inspection_probe(backend: str, iptables_variant: str) -> None:
    print(_firewall(backend, iptables_variant).inspect_ownership().to_json())


def _netns(namespace: str, argv: list[str]) -> list[str]:
    return ["ip", "netns", "exec", namespace, *argv]


def _backend_cli_args(backend: str, iptables_variant: str) -> list[str]:
    return ["--backend", backend, "--iptables-variant", iptables_variant]


def _report_observations(report: dict[str, object]) -> list[dict[str, object]]:
    observations = report.get("tables", report.get("chains"))
    if not isinstance(observations, list):
        raise AssertionError(f"ownership report has no observations: {report}")
    return observations


def _observation_resource(observation: dict[str, object]) -> str:
    resource = observation.get("table", observation.get("chain"))
    if not isinstance(resource, str):
        raise AssertionError(f"ownership observation has no resource: {observation}")
    return resource


def _resource_exists(
    namespace: str,
    backend: str,
    iptables_variant: str,
    resource: str,
) -> bool:
    if backend.startswith("nft-"):
        argv = ["nft", "list", "table", "ip", resource]
    else:
        argv = [
            iptables_variant,
            "--wait",
            "-t",
            "nat",
            "-n",
            "-L",
            resource,
        ]
    return _run(_netns(namespace, argv), check=False).returncode == 0


def _stale_resource(backend: str) -> str:
    return STALE_TABLE if backend.startswith("nft-") else STALE_CHAIN


def _stale_jump_arguments() -> list[str]:
    return [
        "-d",
        f"{LISTEN_ADDRESS}/32",
        "-p",
        "tcp",
        "-m",
        "tcp",
        "--dport",
        str(LISTEN_PORT),
        "-m",
        "comment",
        "--comment",
        f"tcpcc.jump.v1 chain={STALE_CHAIN}",
        "-j",
        STALE_CHAIN,
    ]


def _create_stale_resource(
    namespace: str,
    backend: str,
    iptables_variant: str,
) -> str:
    marker = f"tcpcc.owner.v1 pid=99999999 start=1 tun={STALE_TUN}"
    if backend.startswith("nft-"):
        batch = (
            f"create table ip {STALE_TABLE}\n"
            f"add chain ip {STALE_TABLE} sentinel\n"
            f"add rule ip {STALE_TABLE} sentinel counter comment \"{marker}\"\n"
        )
        _run(
            _netns(namespace, ["nft", "--file", "-"]),
            input_text=batch,
        )
        return _run(
            _netns(namespace, ["nft", "list", "table", "ip", STALE_TABLE])
        ).stdout

    _run(
        _netns(
            namespace,
            [iptables_variant, "--wait", "-t", "nat", "-N", STALE_CHAIN],
        )
    )
    _run(
        _netns(
            namespace,
            [
                iptables_variant,
                "--wait",
                "-t",
                "nat",
                "-A",
                STALE_CHAIN,
                "-m",
                "comment",
                "--comment",
                marker,
                "-j",
                "RETURN",
            ],
        )
    )
    _run(
        _netns(
            namespace,
            [
                iptables_variant,
                "--wait",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                *_stale_jump_arguments(),
            ],
        )
    )
    return _run(
        _netns(namespace, [f"{iptables_variant}-save", "-t", "nat"])
    ).stdout


def _read_stale_resource(
    namespace: str,
    backend: str,
    iptables_variant: str,
) -> str:
    if backend.startswith("nft-"):
        argv = ["nft", "list", "table", "ip", STALE_TABLE]
    else:
        argv = [f"{iptables_variant}-save", "-t", "nat"]
    return _run(_netns(namespace, argv)).stdout


def _delete_stale_resource(
    namespace: str,
    backend: str,
    iptables_variant: str,
) -> None:
    if backend.startswith("nft-"):
        _run(
            _netns(namespace, ["nft", "delete", "table", "ip", STALE_TABLE])
        )
        return
    _run(
        _netns(
            namespace,
            [
                iptables_variant,
                "--wait",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                *_stale_jump_arguments(),
            ],
        )
    )
    for action in ("-F", "-X"):
        _run(
            _netns(
                namespace,
                [
                    iptables_variant,
                    "--wait",
                    "-t",
                    "nat",
                    action,
                    STALE_CHAIN,
                ],
            )
        )


def _wait_ready(process: subprocess.Popen[str]) -> dict[str, object]:
    if process.stdout is None:
        raise RuntimeError("signal worker has no stdout")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        if not selector.select(TIMEOUT):
            raise TimeoutError("signal worker did not become ready")
        line = process.stdout.readline()
    finally:
        selector.close()
    if not line:
        _, stderr = process.communicate(timeout=1.0)
        raise RuntimeError(f"signal worker failed before readiness: {stderr}")
    report = json.loads(line)
    if report.get("status") != "ready":
        raise RuntimeError(f"invalid signal readiness report: {report}")
    return report


def _force_stop(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2.0)


def run_privileged_integration(backend: str, iptables_variant: str) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("composed lifecycle integration must run as root")
    if not Path("/dev/net/tun").is_char_device():
        raise RuntimeError("/dev/net/tun is not an available character device")
    if backend == "nft-lib":
        _firewall(backend, iptables_variant).transport.library_path

    namespace = f"tcc-life-{os.getpid()}-{secrets.token_hex(3)}"
    signal_process: subprocess.Popen[str] | None = None
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    final_report: dict[str, object] | None = None
    namespace_created = False
    try:
        _run(["ip", "netns", "add", namespace])
        namespace_created = True
        _run(["ip", "-n", namespace, "link", "set", "lo", "up"])
        script = str(Path(__file__).resolve())

        failure = json.loads(
            _run(
                _netns(
                    namespace,
                    [
                        sys.executable,
                        script,
                        "--install-failure",
                        *_backend_cli_args(backend, iptables_variant),
                    ],
                )
            ).stdout
        )
        if failure.get("tun_removed") is not True:
            raise AssertionError(f"invalid failure rollback report: {failure}")

        signal_process = subprocess.Popen(
            _netns(
                namespace,
                [
                    sys.executable,
                    script,
                    "--signal-worker",
                    *_backend_cli_args(backend, iptables_variant),
                ],
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        ready = _wait_ready(signal_process)
        tun_name = str(ready["tun"])
        resource_name = str(ready["resource"])
        if ready.get("backend") != backend:
            raise AssertionError(f"signal worker selected wrong backend: {ready}")
        if _run(
            ["ip", "-n", namespace, "link", "show", "dev", tun_name],
            check=False,
        ).returncode != 0:
            raise AssertionError("signal worker TUN was not visible while active")
        active_report = json.loads(
            _run(
                _netns(
                    namespace,
                    [
                        sys.executable,
                        script,
                        "--inspect",
                        *_backend_cli_args(backend, iptables_variant),
                    ],
                )
            ).stdout
        )
        active_resources = _report_observations(active_report)
        if (
            active_report["blocking"]
            or len(active_resources) != 1
            or _observation_resource(active_resources[0]) != resource_name
            or active_resources[0]["status"] != "active"
            or active_resources[0]["owner_pid"] != ready["pid"]
        ):
            raise AssertionError(f"active owner was misclassified: {active_report}")

        signal_process.send_signal(signal.SIGTERM)
        stdout, stderr = signal_process.communicate(timeout=TIMEOUT)
        if signal_process.returncode != 0:
            raise RuntimeError(
                f"signal worker exited with {signal_process.returncode}: {stderr}"
            )
        closed = json.loads(stdout)
        if closed.get("status") != "closed" or closed.get("signal") != signal.SIGTERM:
            raise AssertionError(f"invalid signal cleanup report: {closed}")
        if _run(
            ["ip", "-n", namespace, "link", "show", "dev", tun_name],
            check=False,
        ).returncode == 0:
            raise AssertionError("TUN survived orderly SIGTERM cleanup")
        if _resource_exists(
            namespace,
            backend,
            iptables_variant,
            resource_name,
        ):
            raise AssertionError(
                "DNAT firewall resource survived orderly SIGTERM cleanup"
            )

        stale_before = _create_stale_resource(
            namespace,
            backend,
            iptables_variant,
        )
        stale = json.loads(
            _run(
                _netns(
                    namespace,
                    [
                        sys.executable,
                        script,
                        "--stale",
                        *_backend_cli_args(backend, iptables_variant),
                    ],
                )
            ).stdout
        )
        observations = _report_observations(stale["report"])
        if (
            not stale["blocked_before_tun"]
            or len(observations) != 1
            or _observation_resource(observations[0]) != _stale_resource(backend)
            or observations[0]["status"] != "stale"
        ):
            raise AssertionError(f"invalid stale ownership report: {stale}")
        expected_remediation = (
            f"nft delete table ip {STALE_TABLE}"
            if backend.startswith("nft-")
            else f"{iptables_variant} -t nat -D PREROUTING"
        )
        if expected_remediation not in observations[0]["remediation"]:
            raise AssertionError(f"stale remediation is incomplete: {stale}")
        stale_after = _read_stale_resource(
            namespace,
            backend,
            iptables_variant,
        )
        if stale_after != stale_before:
            raise AssertionError(
                "stale firewall state changed during read-only diagnosis"
            )
        if _run(
            ["ip", "-n", namespace, "link", "show", "dev", STALE_TUN],
            check=False,
        ).returncode == 0:
            raise AssertionError("stale diagnosis acquired a TUN")

        _delete_stale_resource(
            namespace,
            backend,
            iptables_variant,
        )
        final_report = {
            "schema": "tcpcc.composed-lifecycle-integration.v1",
            "backend": backend,
            "iptables_variant": (
                iptables_variant if backend == "iptables" else None
            ),
            "dnat_failure_rolled_back_tun": True,
            "sigterm_removed_tun_and_dnat": True,
            "active_marker_verified": True,
            "stale_resource_blocked_startup": True,
            "stale_resource_left_untouched": True,
            "operator_cleanup_explicit": True,
        }
    except BaseException as error:
        primary_error = error
    finally:
        _force_stop(signal_process)
        if namespace_created:
            deleted = _run(["ip", "netns", "delete", namespace], check=False)
            if deleted.returncode != 0:
                cleanup_errors.append(deleted.stderr.strip())

    remaining = _run(["ip", "netns", "list"]).stdout
    if namespace in {line.split()[0] for line in remaining.splitlines() if line}:
        cleanup_errors.append(f"namespace survived cleanup: {namespace}")
    if primary_error is not None:
        if cleanup_errors:
            raise RuntimeError(
                "integration failed and cleanup was incomplete: "
                + "; ".join(cleanup_errors)
            ) from primary_error
        raise primary_error
    if cleanup_errors:
        raise RuntimeError("integration cleanup failed: " + "; ".join(cleanup_errors))
    if final_report is None:
        raise RuntimeError("integration produced no report")
    print(json.dumps(final_report, sort_keys=True, separators=(",", ":")))


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--integration", action="store_true")
    mode.add_argument("--install-failure", action="store_true")
    mode.add_argument("--signal-worker", action="store_true")
    mode.add_argument("--stale", action="store_true")
    mode.add_argument("--inspect", action="store_true")
    parser.add_argument("--backend", choices=BACKENDS, default="nft-exec")
    parser.add_argument(
        "--iptables-variant",
        choices=IPTABLES_VARIANTS,
        default="iptables",
    )
    arguments = parser.parse_args()

    if arguments.integration:
        run_privileged_integration(arguments.backend, arguments.iptables_variant)
    elif arguments.install_failure:
        run_install_failure_probe(arguments.backend, arguments.iptables_variant)
    elif arguments.signal_worker:
        run_signal_worker(arguments.backend, arguments.iptables_variant)
    elif arguments.inspect:
        run_inspection_probe(arguments.backend, arguments.iptables_variant)
    else:
        run_stale_probe(arguments.backend, arguments.iptables_variant)


if __name__ == "__main__":
    main()

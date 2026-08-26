#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Privileged failure, signal, and stale-resource tests for M8.3."""

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
    NftOwnershipReport,
    PreflightReport,
    ShutdownSignals,
    StaleOwnershipError,
    TunConfig,
    acquire_host_network,
    create_tun_queue,
    inspect_nft_ownership,
    install_nft_dnat,
)

LISTEN_ADDRESS = "203.0.113.10"
LISTEN_PORT = 18443
TUN_HOST = "198.19.0.1"
TUN_GUEST = "198.19.0.2"
TARGET_PORT = 28443
STALE_TABLE = "tcpcc_stale_ci"
STALE_TUN = "tcpcc-stale0"
FAIL_TABLE = "tcpcc_fail_ci"
TIMEOUT = 20.0


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


def _config(*, tun_name: str | None = None) -> HostNetworkConfig:
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
    )


def run_install_failure_probe() -> None:
    acquired = {}
    _run(["nft", "create", "table", "ip", FAIL_TABLE])
    table_before = _run(
        ["nft", "list", "table", "ip", FAIL_TABLE]
    ).stdout

    def acquire_tun(config: TunConfig):
        queue = create_tun_queue(config)
        acquired["queue"] = queue
        return queue

    def reject_dnat(config: NftDnatConfig, ownership):
        return install_nft_dnat(
            NftDnatConfig(
                listen_address=config.listen_address,
                listen_port=config.listen_port,
                target_address=config.target_address,
                target_port=config.target_port,
                table_name=FAIL_TABLE,
            ),
            ownership=ownership,
        )

    try:
        acquire_host_network(
            _config(tun_name="tcpcc-fail0"),
            preflight_collector=_green_preflight,
            ownership_collector=lambda: NftOwnershipReport(()),
            tun_acquirer=acquire_tun,
            dnat_acquirer=reject_dnat,
        )
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError("injected nft failure unexpectedly succeeded")

    queue = acquired["queue"]
    link = _run(
        ["ip", "link", "show", "dev", queue.name],
        check=False,
    )
    if not queue.closed or link.returncode == 0:
        raise AssertionError("TUN survived failed DNAT acquisition")
    table_after = _run(
        ["nft", "list", "table", "ip", FAIL_TABLE]
    ).stdout
    if table_after != table_before:
        raise AssertionError("rejected DNAT transaction changed existing table")
    _run(["nft", "delete", "table", "ip", FAIL_TABLE])
    print(
        json.dumps(
            {
                "dnat_failure_reported": True,
                "existing_table_unchanged": True,
                "tun_removed": True,
                "tun": queue.name,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def run_signal_worker() -> None:
    lease = None
    with ShutdownSignals() as shutdown:
        lease = acquire_host_network(
            _config(),
            preflight_collector=_green_preflight,
        )
        try:
            print(
                json.dumps(
                    {
                        "status": "ready",
                        "pid": os.getpid(),
                        "tun": lease.tun_name,
                        "table": lease.table_name,
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


def run_stale_probe() -> None:
    report = inspect_nft_ownership()
    called = False

    def forbidden_tun(_config: TunConfig):
        nonlocal called
        called = True
        raise AssertionError("stale ownership allowed TUN acquisition")

    try:
        acquire_host_network(
            _config(tun_name=STALE_TUN),
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


def run_inspection_probe() -> None:
    print(inspect_nft_ownership().to_json())


def _netns(namespace: str, argv: list[str]) -> list[str]:
    return ["ip", "netns", "exec", namespace, *argv]


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


def run_privileged_integration() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("composed lifecycle integration must run as root")
    if not Path("/dev/net/tun").is_char_device():
        raise RuntimeError("/dev/net/tun is not an available character device")

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
                _netns(namespace, [sys.executable, script, "--install-failure"])
            ).stdout
        )
        if failure.get("tun_removed") is not True:
            raise AssertionError(f"invalid failure rollback report: {failure}")

        signal_process = subprocess.Popen(
            _netns(namespace, [sys.executable, script, "--signal-worker"]),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        ready = _wait_ready(signal_process)
        tun_name = str(ready["tun"])
        table_name = str(ready["table"])
        if _run(
            ["ip", "-n", namespace, "link", "show", "dev", tun_name],
            check=False,
        ).returncode != 0:
            raise AssertionError("signal worker TUN was not visible while active")
        table_json = json.loads(
            _run(
                _netns(namespace, ["nft", "--json", "list", "ruleset", "ip"])
            ).stdout
        )
        marker = ""
        for entry in table_json["nftables"]:
            rule = entry.get("rule", {})
            if rule.get("table") == table_name:
                marker = rule.get("comment", "")
        if not marker.startswith(f"tcpcc.owner.v1 pid={ready['pid']} "):
            raise AssertionError(f"owned table marker is missing: {table_json}")
        active_report = json.loads(
            _run(
                _netns(namespace, [sys.executable, script, "--inspect"])
            ).stdout
        )
        active_tables = active_report["tables"]
        if (
            active_report["blocking"]
            or len(active_tables) != 1
            or active_tables[0]["table"] != table_name
            or active_tables[0]["status"] != "active"
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
        if _run(
            _netns(namespace, ["nft", "list", "table", "ip", table_name]),
            check=False,
        ).returncode == 0:
            raise AssertionError("DNAT table survived orderly SIGTERM cleanup")

        stale_batch = (
            f"create table ip {STALE_TABLE}\n"
            f"add chain ip {STALE_TABLE} sentinel\n"
            f"add rule ip {STALE_TABLE} sentinel counter comment "
            f'"tcpcc.owner.v1 pid=99999999 start=1 tun={STALE_TUN}"\n'
        )
        _run(
            _netns(namespace, ["nft", "--file", "-"]),
            input_text=stale_batch,
        )
        stale_before = _run(
            _netns(namespace, ["nft", "list", "table", "ip", STALE_TABLE])
        ).stdout
        stale = json.loads(
            _run(_netns(namespace, [sys.executable, script, "--stale"])).stdout
        )
        observations = stale["report"]["tables"]
        if not stale["blocked_before_tun"] or observations[0]["status"] != "stale":
            raise AssertionError(f"invalid stale ownership report: {stale}")
        if (
            f"nft delete table ip {STALE_TABLE}"
            not in observations[0]["remediation"]
        ):
            raise AssertionError(f"stale remediation is incomplete: {stale}")
        stale_after = _run(
            _netns(namespace, ["nft", "list", "table", "ip", STALE_TABLE])
        ).stdout
        if stale_after != stale_before:
            raise AssertionError("stale table changed during read-only diagnosis")
        if _run(
            ["ip", "-n", namespace, "link", "show", "dev", STALE_TUN],
            check=False,
        ).returncode == 0:
            raise AssertionError("stale diagnosis acquired a TUN")

        _run(
            _netns(namespace, ["nft", "delete", "table", "ip", STALE_TABLE])
        )
        final_report = {
            "schema": "tcpcc.composed-lifecycle-integration.v1",
            "dnat_failure_rolled_back_tun": True,
            "sigterm_removed_tun_and_dnat": True,
            "active_marker_verified": True,
            "stale_table_blocked_startup": True,
            "stale_table_left_untouched": True,
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
    arguments = parser.parse_args()

    if arguments.integration:
        run_privileged_integration()
    elif arguments.install_failure:
        run_install_failure_probe()
    elif arguments.signal_worker:
        run_signal_worker()
    elif arguments.inspect:
        run_inspection_probe()
    else:
        run_stale_probe()


if __name__ == "__main__":
    main()

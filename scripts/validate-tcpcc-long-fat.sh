#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${TCPCC_LINK_OUT:-$ROOT/.build/tcpcc-bootstrap-out}"
KERNEL="${TCPCC_LONG_FAT_KERNEL:-$OUT/vmlinux}"
TUN_NAME="${TCPCC_LONG_FAT_TUN_NAME:-tcpcc-bdp}"
HOST_ADDR="192.0.2.1"
GUEST_ADDR="192.0.2.2"
DELAY_MS="${TCPCC_LONG_FAT_DELAY_MS:-50}"
GUEST_TO_HOST_BYTES="${TCPCC_LONG_FAT_GUEST_TO_HOST_BYTES:-2097152}"
HOST_TO_GUEST_BYTES="${TCPCC_LONG_FAT_HOST_TO_GUEST_BYTES:-16384}"
BOOT_LOG="$ROOT/.build/tcpcc-long-fat-bootstrap.log"
CONTROL_RESPONSES="$ROOT/.build/tcpcc-long-fat-control.responses"
PING_LOG="$ROOT/.build/tcpcc-long-fat-ping.log"
TCP_LOG="$ROOT/.build/tcpcc-long-fat-tcp.log"
LINK_LOG="$ROOT/.build/tcpcc-long-fat-link.txt"
QDISC_LOG="$ROOT/.build/tcpcc-long-fat-qdisc.txt"

if [[ ! -x "$KERNEL" ]]; then
  echo "M6.4 requires an already-linked executable tcpcc vmlinux: $KERNEL" >&2
  exit 1
fi
if [[ ! -c /dev/net/tun ]]; then
  echo "M6.4 requires host /dev/net/tun" >&2
  exit 1
fi
for command in ip ping sudo tc; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "M6.4 requires host command: $command" >&2
    exit 1
  fi
done
if ! sudo -n true; then
  echo "M6.4 CI adapter requires passwordless sudo for host TUN/netem configuration" >&2
  exit 1
fi

cleanup() {
  sudo -n tc qdisc del dev "$TUN_NAME" root >/dev/null 2>&1 || true
  sudo -n ip tuntap del dev "$TUN_NAME" mode tun >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

sudo -n ip tuntap add dev "$TUN_NAME" mode tun user "$(id -un)"
sudo -n ip addr add "$HOST_ADDR/32" peer "$GUEST_ADDR/32" dev "$TUN_NAME"
if [[ -e "/proc/sys/net/ipv6/conf/$TUN_NAME/disable_ipv6" ]]; then
  printf '1\n' | sudo -n tee "/proc/sys/net/ipv6/conf/$TUN_NAME/disable_ipv6" >/dev/null
fi
sudo -n ip link set dev "$TUN_NAME" mtu 1500 up
sudo -n tc qdisc replace dev "$TUN_NAME" root netem delay "${DELAY_MS}ms" limit 10000

mkdir -p "$ROOT/.build"
ip -details addr show dev "$TUN_NAME" > "$LINK_LOG"
rm -f "$BOOT_LOG" "$CONTROL_RESPONSES" "$PING_LOG" "$TCP_LOG" "$QDISC_LOG"

python3 "$ROOT/scripts/run-tcpcc-tun-test.py" \
  --kernel "$KERNEL" \
  --tun-name "$TUN_NAME" \
  --boot-log "$BOOT_LOG" \
  --responses "$CONTROL_RESPONSES" \
  --ping-log "$PING_LOG" \
  --tcp-log "$TCP_LOG" \
  --guest-to-host-bytes "$GUEST_TO_HOST_BYTES" \
  --host-to-guest-bytes "$HOST_TO_GUEST_BYTES"

tc -s qdisc show dev "$TUN_NAME" > "$QDISC_LOG"

cat "$PING_LOG"
cat "$TCP_LOG"
cat "$QDISC_LOG"
cat "$BOOT_LOG"

grep -F 'tcpcc: M5.1 L3 netdevice tcpcc' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M6.1 root qdisc fq active on tcpcc0' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M5.1 hosted L3 netdevice passed (' "$BOOT_LOG" >/dev/null
grep -F 'Kernel panic - not syncing: tcpcc: M5.1 reached hosted L3 netdevice boundary after packet-fd validation' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc-host: panic boundary -> exit(86)' "$BOOT_LOG" >/dev/null

grep -F "cubic: guest=192.0.2.2 host=192.0.2.1:" "$TCP_LOG" >/dev/null
grep -F "bbr: guest=192.0.2.2 host=192.0.2.1:" "$TCP_LOG" >/dev/null
grep -F "guest_to_host=$GUEST_TO_HOST_BYTES host_to_guest=$HOST_TO_GUEST_BYTES" "$TCP_LOG" >/dev/null

grep -F "${TUN_NAME}:" "$LINK_LOG" >/dev/null
grep -F 'mtu 1500' "$LINK_LOG" >/dev/null
grep -F "inet $HOST_ADDR peer $GUEST_ADDR/32" "$LINK_LOG" >/dev/null
grep -F 'qdisc netem' "$QDISC_LOG" >/dev/null
grep -F "delay ${DELAY_MS}ms" "$QDISC_LOG" >/dev/null

python3 - "$QDISC_LOG" "$PING_LOG" "$TCP_LOG" "$DELAY_MS" <<'PY'
import re
import sys
from pathlib import Path

qdisc = Path(sys.argv[1]).read_text(encoding="utf-8")
ping = Path(sys.argv[2]).read_text(encoding="utf-8")
tcp_log = Path(sys.argv[3]).read_text(encoding="utf-8")
delay_ms = float(sys.argv[4])

match = re.search(
    r"Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt\s+\(dropped\s+(\d+)",
    qdisc,
)
if match is None:
    raise SystemExit("cannot parse netem qdisc counters")
bytes_sent, packets_sent, dropped = map(int, match.groups())
if bytes_sent <= 0 or packets_sent <= 0:
    raise SystemExit("netem qdisc did not carry test traffic")
if dropped != 0:
    raise SystemExit(f"lossless netem qdisc dropped {dropped} packets")

rtt = re.search(
    r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = "
    r"[0-9.]+/([0-9.]+)/[0-9.]+/[0-9.]+ ms",
    ping,
)
if rtt is None:
    raise SystemExit("cannot parse delayed-path ping RTT")
avg_rtt_ms = float(rtt.group(1))
minimum_rtt_ms = delay_ms * 0.60
if avg_rtt_ms < minimum_rtt_ms:
    raise SystemExit(
        f"delayed path RTT too small: avg={avg_rtt_ms:.3f}ms "
        f"minimum={minimum_rtt_ms:.3f}ms"
    )

telemetry: dict[str, dict[str, int]] = {}
for line in tcp_log.splitlines():
    if not line.startswith(("cubic:", "bbr:")):
        continue
    cc_name = line.split(":", 1)[0]
    fields: dict[str, int] = {}
    for key, value in re.findall(r"([a-z_]+)=([0-9]+)", line):
        fields[key] = int(value)
    telemetry[cc_name] = fields

for cc_name in ("cubic", "bbr"):
    fields = telemetry.get(cc_name)
    if fields is None:
        raise SystemExit(f"missing {cc_name} TCP telemetry")
    if fields.get("state") != 1:
        raise SystemExit(f"{cc_name} telemetry is not ESTABLISHED: {fields.get('state')}")
    if fields.get("snd_cwnd", 0) <= 0:
        raise SystemExit(f"{cc_name} telemetry has zero snd_cwnd")
    if fields.get("rto_us", 0) <= 0:
        raise SystemExit(f"{cc_name} telemetry has zero RTO")
    if fields.get("rtt_us", 0) <= 0:
        raise SystemExit(f"{cc_name} telemetry has zero RTT")
    minimum_tcp_rtt_us = int(delay_ms * 1000.0 * 0.60)
    if fields["rtt_us"] < minimum_tcp_rtt_us:
        raise SystemExit(
            f"{cc_name} TCP_INFO RTT too small: {fields['rtt_us']}us "
            f"minimum={minimum_tcp_rtt_us}us"
        )

bbr = telemetry["bbr"]
if bbr.get("pacing_rate", 0) <= 0:
    raise SystemExit("BBR telemetry has zero pacing_rate")
if bbr.get("max_pacing_rate", 0) <= 0:
    raise SystemExit("BBR telemetry has zero max_pacing_rate")

print(
    f"netem verified: packets={packets_sent} bytes={bytes_sent} "
    f"dropped={dropped} avg_rtt_ms={avg_rtt_ms:.3f}"
)
for cc_name in ("cubic", "bbr"):
    fields = telemetry[cc_name]
    print(
        f"{cc_name} TCP_INFO verified: rtt_us={fields['rtt_us']} "
        f"rto_us={fields['rto_us']} snd_cwnd={fields['snd_cwnd']} "
        f"pacing_rate={fields.get('pacing_rate', 0)} "
        f"max_pacing_rate={fields.get('max_pacing_rate', 0)} "
        f"delivery_rate={fields.get('delivery_rate', 0)}"
    )
PY

printf 'M6.4 delayed-path TCP_INFO/pacing passed CUBIC+BBR (%sms, %s guest->host bytes each)\n' "$DELAY_MS" "$GUEST_TO_HOST_BYTES"

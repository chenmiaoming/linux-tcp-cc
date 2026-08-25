#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${TCPCC_LINK_OUT:-$ROOT/.build/tcpcc-bootstrap-out}"
KERNEL="${TCPCC_TUN_KERNEL:-$OUT/vmlinux}"
TUN_NAME="${TCPCC_TUN_NAME:-tcpcc-ci}"
HOST_ADDR="192.0.2.1"
GUEST_ADDR="192.0.2.2"
BOOT_LOG="$ROOT/.build/tcpcc-tun-bootstrap.log"
CONTROL_RESPONSES="$ROOT/.build/tcpcc-tun-control.responses"
PING_LOG="$ROOT/.build/tcpcc-tun-ping.log"
TCP_LOG="$ROOT/.build/tcpcc-tun-tcp.log"
LINK_LOG="$ROOT/.build/tcpcc-tun-link.txt"

if [[ ! -x "$KERNEL" ]]; then
  echo "M6.2 requires an already-linked executable tcpcc vmlinux: $KERNEL" >&2
  exit 1
fi
if [[ ! -c /dev/net/tun ]]; then
  echo "M6.2 requires host /dev/net/tun" >&2
  exit 1
fi
for command in ip ping sudo; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "M6.2 requires host command: $command" >&2
    exit 1
  fi
done
if ! sudo -n true; then
  echo "M6.2 CI adapter requires passwordless sudo for host TUN configuration" >&2
  exit 1
fi

cleanup() {
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

mkdir -p "$ROOT/.build"
ip -details addr show dev "$TUN_NAME" > "$LINK_LOG"
rm -f "$BOOT_LOG" "$CONTROL_RESPONSES" "$PING_LOG" "$TCP_LOG"

python3 "$ROOT/scripts/run-tcpcc-tun-test.py" \
  --kernel "$KERNEL" \
  --tun-name "$TUN_NAME" \
  --boot-log "$BOOT_LOG" \
  --responses "$CONTROL_RESPONSES" \
  --ping-log "$PING_LOG" \
  --tcp-log "$TCP_LOG" \
  --exercise-listeners

cat "$PING_LOG"
cat "$TCP_LOG"
cat "$BOOT_LOG"

grep -F 'tcpcc: M5.1 L3 netdevice tcpcc' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M6.1 root qdisc fq active on tcpcc0' "$BOOT_LOG" >/dev/null
grep -F 'tcpcc: M5.1 hosted L3 netdevice passed (' "$BOOT_LOG" >/dev/null
grep -F 'Kernel panic - not syncing: tcpcc: M5.1 reached hosted L3 netdevice boundary after packet-fd validation' \
  "$BOOT_LOG" >/dev/null
grep -F 'tcpcc-host: panic boundary -> exit(86)' "$BOOT_LOG" >/dev/null

grep -F 'cubic: guest=192.0.2.2 host=192.0.2.1:' "$TCP_LOG" >/dev/null
grep -F 'bbr: guest=192.0.2.2 host=192.0.2.1:' "$TCP_LOG" >/dev/null
grep -F 'guest_to_host=16384 host_to_guest=16384' "$TCP_LOG" >/dev/null
grep -F 'listener-cubic: guest=192.0.2.2:18443 host=192.0.2.1:' "$TCP_LOG" >/dev/null
grep -F 'listener-bbr: guest=192.0.2.2:18444 host=192.0.2.1:' "$TCP_LOG" >/dev/null
grep -F 'listener_cc=cubic accepted_cc=cubic' "$TCP_LOG" >/dev/null
grep -F 'listener_cc=bbr accepted_cc=bbr' "$TCP_LOG" >/dev/null
grep -F 'server_to_client=16384 client_to_server=16384' "$TCP_LOG" >/dev/null

grep -F "${TUN_NAME}:" "$LINK_LOG" >/dev/null
grep -F 'mtu 1500' "$LINK_LOG" >/dev/null
grep -F "inet $HOST_ADDR peer $GUEST_ADDR/32" "$LINK_LOG" >/dev/null

printf 'M8.1 real TUN adapter passed outbound and inbound TCP with CUBIC and BBR\n'

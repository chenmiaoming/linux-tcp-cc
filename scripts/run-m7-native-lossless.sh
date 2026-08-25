#!/usr/bin/env bash
set -euo pipefail

probe=${1:?usage: run-m7-native-lossless.sh PROBE}
sender_ns=m7-sender
receiver_ns=m7-receiver
sender_dev=m7tx0
receiver_dev=m7rx0
sender_ip=192.0.2.2
receiver_ip=192.0.2.1
tx_bytes=2097152
rx_bytes=16384

cleanup() {
  ip netns del "$sender_ns" 2>/dev/null || true
  ip netns del "$receiver_ns" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

if [[ $(id -u) -ne 0 ]]; then
  echo "M7 native reference requires root inside the guest" >&2
  exit 1
fi
if [[ ! -x "$probe" ]]; then
  echo "M7 native TCP probe is not executable: $probe" >&2
  exit 1
fi

kernel_release=$(uname -r)
clocksource=$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource)
echo "M7_NATIVE_KERNEL_RELEASE=$kernel_release"
echo "M7_NATIVE_CLOCKSOURCE=$clocksource"

ip netns add "$sender_ns"
ip netns add "$receiver_ns"
ip link add "$sender_dev" type veth peer name "$receiver_dev"
ip link set "$sender_dev" netns "$sender_ns"
ip link set "$receiver_dev" netns "$receiver_ns"
ip -n "$sender_ns" link set lo up
ip -n "$receiver_ns" link set lo up
ip -n "$sender_ns" addr add "$sender_ip/24" dev "$sender_dev"
ip -n "$receiver_ns" addr add "$receiver_ip/24" dev "$receiver_dev"
ip -n "$sender_ns" link set "$sender_dev" up
ip -n "$receiver_ns" link set "$receiver_dev" up

ip netns exec "$sender_ns" tc qdisc replace dev "$sender_dev" root fq
ip netns exec "$receiver_ns" tc qdisc replace dev "$receiver_dev" root \
  netem delay 50ms loss 0% limit 10000

if ! ip netns exec "$sender_ns" tc qdisc show dev "$sender_dev" | grep -q '^qdisc fq '; then
  echo "M7 native sender root qdisc is not fq" >&2
  exit 1
fi
if ! ip netns exec "$receiver_ns" tc qdisc show dev "$receiver_dev" | grep -q '^qdisc netem '; then
  echo "M7 native ACK-path qdisc is not netem" >&2
  exit 1
fi

available_cc=$(ip netns exec "$sender_ns" \
  cat /proc/sys/net/ipv4/tcp_available_congestion_control)
echo "M7_NATIVE_AVAILABLE_CC=$available_cc"
for cc in cubic bbr; do
  if [[ " $available_cc " != *" $cc "* ]]; then
    echo "M7 native congestion control unavailable: $cc" >&2
    exit 1
  fi
done

echo "M7_NATIVE_PING_BEGIN"
ip netns exec "$sender_ns" ping -n -c 5 -W 2 "$receiver_ip"
echo "M7_NATIVE_PING_END"

port=45100
for cc in cubic bbr; do
  port=$((port + 1))
  ip netns exec "$receiver_ns" "$probe" server "$receiver_ip" "$port" \
    "$tx_bytes" "$rx_bytes" &
  server_pid=$!
  ip netns exec "$sender_ns" "$probe" client "$receiver_ip" "$port" "$cc" \
    "$tx_bytes" "$rx_bytes"
  wait "$server_pid"
done

echo "M7_NATIVE_QDISC_BEGIN"
ip netns exec "$receiver_ns" tc -s qdisc show dev "$receiver_dev"
echo "M7_NATIVE_QDISC_END"
echo "M7_NATIVE_LOSSLESS_DONE"

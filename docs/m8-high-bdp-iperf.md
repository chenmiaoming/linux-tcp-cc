# M8 high-BDP lossy iperf comparison

This gate compares the shipped tcpcc server-ingress path with ordinary native
Linux TCP under the same emulated bottleneck. It measures delivered application
goodput rather than treating an end-of-flow TCP telemetry snapshot as a
throughput benchmark.

## Measurement direction

Every client uses single-stream `iperf3 --reverse`. The server is therefore the
bulk-data sender, which makes its congestion-control algorithm the one under
test:

```text
native CUBIC sender ----\
native BBR sender -------+--> bottleneck router --> iperf3 client
tcpcc public BBR sender -/
```

A normal forward iperf test would measure the client namespace's congestion
control and would not test the algorithm selected by `tcpcc --cc`.

For tcpcc, the iperf server remains an ordinary loopback backend. Its TCP
connection ends at the bridge and is not the measured public connection. The
`tcpcc.runtime.v1` events must independently prove that every accepted public
socket inherited BBR.

## Network contract

The benchmark creates three disposable network namespaces:

```text
server namespace -- veth -- bottleneck namespace -- veth -- client namespace
       fq                         netem                      fq
```

The bottleneck applies the same policy in each direction:

- 50 Mbit/s rate;
- 50 ms one-way delay, for an expected 100 ms RTT;
- 0.1% independent random packet loss;
- MTU 1500;
- 20,000-packet queue limit.

The resulting configured path BDP is 625,000 bytes. Endpoint offloads are
disabled so netem loss is applied to ordinary packets rather than large veth
GSO aggregates. Endpoint `fq` remains intact so native and hosted BBR can use
socket pacing before packets enter the separate bottleneck.

The checked-in contract is
[`benchmarks/m8/iperf-high-bdp-loss-v1.json`](../benchmarks/m8/iperf-high-bdp-loss-v1.json).
Changing a network parameter, duration, repetition count, or acceptance bound
therefore produces a reviewable scenario change.

## Repetitions and results

The three paths are run three times in a rotating Latin-square order. Each
measurement has a two-second omitted warm-up followed by ten reported seconds.
The report retains every raw iperf JSON document and computes the median
delivered goodput and retransmissions for:

- native CUBIC;
- native BBR;
- tcpcc public-side BBR.

The native paths use the GitHub runner kernel and report its release. tcpcc uses
the pinned hosted Linux image built by the prerequisite CI job. Consequently,
BBR-over-CUBIC ratios are prominent observations but are not semantic parity
claims between two identical kernels.

The v1 hard performance bound requires tcpcc BBR median goodput to remain from
0.5 through 1.5 times native BBR. This deliberately broad shared-runner band
catches a major runtime/data-path regression without promising identical
timing between different kernels. Each individual run must also deliver at
least 1 Mbit/s. Both netem directions must record loss near the configured
order of magnitude, while endpoint `fq` must not drop packets.

iperf3 normally closes its reverse data socket abortively after a successful
measurement. A completed tcpcc data flow may therefore end with clean EOF or
`ECONNRESET`; the control flow must close cleanly, and cancellation or another
terminal errno is always a failure.

## Running the gate

After building the hosted kernel, run as root on a disposable Linux host with
TUN, BBR, nftables, iproute2, ethtool, and iperf3:

```bash
sudo python3 scripts/run-tcpcc-high-bdp-iperf.py \
  --integration \
  --kernel .build/tcpcc-bootstrap-out/vmlinux \
  --scenario-file benchmarks/m8/iperf-high-bdp-loss-v1.json \
  --output-dir .build/m8-high-bdp
```

GitHub Actions publishes the complete directory as
`tcpcc-m85-high-bdp-iperf`, including `report.json`, all nine raw iperf JSON
documents, tcpcc events and diagnostics, ping output, topology state, and
before/after qdisc counters.

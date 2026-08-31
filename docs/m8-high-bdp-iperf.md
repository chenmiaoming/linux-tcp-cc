# Transoceanic extreme-network comparison

This CI experiment compares the shipped tcpcc server-ingress path with ordinary native
Linux TCP under the same emulated bottleneck. It measures delivered application
goodput rather than treating an end-of-flow TCP telemetry snapshot as a
throughput benchmark.

## Measurement direction

Every client uses single-stream `iperf3 --reverse`. The server is therefore the
bulk-data sender, which makes its congestion-control algorithm the one under
test:

```text
native CUBIC sender -----\
native BBR sender --------+--> bottleneck router --> iperf3 client
tcpcc public CUBIC sender -+
tcpcc public BBR sender --/
```

A normal forward iperf test would measure the client namespace's congestion
control and would not test the algorithm selected by `tcpcc --cc`.

For tcpcc, the iperf server remains an ordinary loopback backend. Its TCP
connection ends at the bridge and is not the measured public connection. The
`tcpcc.runtime.v1` events must independently prove that every accepted public
socket inherited the selected CUBIC or BBR algorithm.

## Network contract

The benchmark creates three disposable network namespaces:

```text
server namespace -- veth -- bottleneck namespace -- veth -- client namespace
       fq                         netem                      fq
```

The bottleneck applies the same policy in each direction:

- 1,000 Mbit/s rate;
- 100 ms one-way delay, for an expected 200 ms RTT;
- 10% independent random packet loss in each direction;
- MTU 1500;
- 40,000-packet queue limit.

The resulting configured path BDP is 25,000,000 bytes. Endpoint offloads are
disabled so netem loss is applied to ordinary packets rather than large veth
GSO aggregates. Endpoint `fq` remains intact so native and hosted BBR can use
socket pacing before packets enter the separate bottleneck.

The checked-in contract is
[`benchmarks/m8/iperf-transoceanic-extreme-v1.json`](../benchmarks/m8/iperf-transoceanic-extreme-v1.json).
Changing a network parameter, duration, repetition count, or acceptance bound
therefore produces a reviewable scenario change.

## Repetitions and results

The four paths are run three times in rotating order. Each measurement has a
five-second omitted warm-up followed by fifteen reported seconds.
The report retains every raw iperf JSON document and computes the median
delivered goodput and retransmissions for:

- native CUBIC;
- native BBR;
- tcpcc public-side CUBIC; and
- tcpcc public-side BBR.

The native paths use the GitHub runner kernel and report its release. tcpcc uses
the pinned hosted Linux image built by the prerequisite CI job. Consequently,
BBR-over-CUBIC ratios are prominent observations but are not semantic parity
claims between two identical kernels.

Goodput, retransmissions, and all cross-path ratios are observations rather
than merge gates. At symmetric 10% random loss, short shared-runner samples are
too variable for a stable ranking threshold. CI still fails if a measurement
cannot complete, a requested congestion-control algorithm is not actually in
use, the configured qdisc delay/loss/rate contract drifts, endpoint `fq` drops packets,
or either TCPCC instance fails to shut down and remove its resources.

Twenty ICMP samples record min/average/median/max RTT. The median is an
observation rather than a gate because runner scheduling and severe loss can
produce large delayed outliers; the exact qdisc delay remains a hard gate.

Goodput is end-to-end and directly comparable across all four paths. iperf's
native retransmit count belongs to the public WAN sender. On a TCPCC path,
iperf sees the ordinary backend loopback sender instead; the hosted public
socket's retransmit counter is not currently exported. The report labels this
scope explicitly, and TCPCC/native retransmit totals must not be compared.

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
  --scenario-file benchmarks/m8/iperf-transoceanic-extreme-v1.json \
  --packet-trace \
  --output-dir .build/transoceanic-extreme
```

GitHub Actions runs the experiment weekly, on manual request, and when its own
contract changes. It publishes the complete directory for 30 days, including
`report.json`, all twelve raw iperf JSON documents, both TCPCC event streams and
diagnostics, ping output, topology state, and before/after qdisc counters.

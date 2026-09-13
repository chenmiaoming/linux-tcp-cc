# Transoceanic extreme-network comparison

> This document defines a benchmark contract, not the overall product
> architecture. For the current ownership model, start with
> [`../ARCHITECTURE.md`](../ARCHITECTURE.md). The original M8 experiments
> predated the current TCP-memory policy; historical runs that used an automatic
> 4-MiB hosted `tcp_wmem` ceiling must not be read as the current default.

This CI experiment compares the shipped tcpcc server-ingress path with ordinary
native Linux TCP under the same emulated bottleneck. It measures delivered
application goodput rather than treating an end-of-flow TCP telemetry snapshot
as a throughput benchmark.

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
native runtime's `ready` event proves that the requested algorithm was set and
read back on the hosted public listener before service exposure, while
aggregate `service-stats` prove that the benchmark flows were accepted and
completed by that hosted service. The lower-level real-TUN regression separately
checks accepted-socket congestion-control inheritance through the upstream Linux
accept path.

The benchmark intentionally does **not** claim a per-flow accepted-socket
`TCP_CONGESTION` readback from `tcpcc.runtime.v1`: the current native production
event stream is aggregate and has no per-flow `connection-opened` event. The
legacy report key named `accepted_cc` currently records the algorithm already
validated on the hosted listener; it should not be interpreted as an
independent per-accepted-socket measurement.

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

The server namespace's outer-host default congestion control is fixed to CUBIC
while both tcpcc public CUBIC and public BBR instances run. This is an
architectural regression check: hosted BBR must remain selectable and usable
without changing the outer host's default TCP congestion control. The native
BBR comparison is a separate native-kernel case and therefore still requires
BBR to be available in the runner kernel.

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

Current production policy preserves the `tcp_wmem[2]` and aggregate `tcp_mem`
values derived by upstream Linux `tcp_init()` from the configured hosted RAM.
On the current kernel a 128-MiB arena therefore has a send autotuning ceiling of
roughly 1 MiB rather than being automatically raised to 4 MiB. This is the
policy exercised by the checked-in high-BDP harness unless an explicit
`--tcp-wmem-max-kib` override is added to that experiment.

Earlier M8-era work temporarily raised the 128-MiB default send ceiling toward
4 MiB to improve one high-BDP case. Later real-machine memory qualification
showed that changing the per-socket ceiling without preserving the matching
RAM-derived aggregate policy was the wrong default. PR #119 restored upstream
`tcp_wmem`/`tcp_mem` policy by default. An operator or qualification experiment
may still raise the send ceiling explicitly; when that override exceeds the
upstream value, tcpcc raises the aggregate TCP-memory budget only enough to keep
approximately the upstream pressure-to-send-ceiling scale, subject to its hosted
RAM safety cap. Historical benchmark numbers collected under the old automatic
4-MiB policy are therefore a different configuration and should not be compared
as if they were current-default results.

The native paths use the GitHub runner kernel and report its release. tcpcc uses
the pinned hosted Linux image built by the prerequisite CI job. Consequently,
BBR-over-CUBIC ratios are prominent observations but are not semantic parity
claims between two identical kernels.

Goodput, retransmissions, and all cross-path ratios are observations rather
than merge gates. At symmetric 10% random loss, short shared-runner samples are
too variable for a stable ranking threshold. CI still fails if a measurement
cannot complete, the requested listener congestion control cannot be selected,
the configured qdisc delay/loss/rate contract drifts, endpoint `fq` drops
packets, or either TCPCC instance fails to shut down and remove its resources.

Twenty ICMP samples record min/average/median/max RTT. The median is an
observation rather than a gate because runner scheduling and severe loss can
produce large delayed outliers; the exact qdisc delay remains a hard gate.

Goodput is end-to-end and directly comparable across all four paths. iperf's
native retransmit count belongs to the public WAN sender. On a TCPCC path,
iperf sees the ordinary backend loopback sender instead; the hosted public
socket's retransmit counter is not currently exported. The report labels this
scope explicitly, and TCPCC/native retransmit totals must not be compared.

iperf3 normally closes its reverse data socket abortively after a successful
measurement. A completed tcpcc data flow may therefore end with clean EOF,
`EPIPE`, or `ECONNRESET`; the control flow must close cleanly, and cancellation
or another terminal errno is always a failure.

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

BBR in that prerequisite list is needed by the **native BBR comparison case**,
not by tcpcc's hosted BBR listener. A tcpcc-only deployment does not require
outer-host BBR.

`--packet-trace` is optional and retains only the first 160 bytes of each
public packet for sequence/pacing diagnosis. Scheduled and pull-request runs
leave it disabled; a manual workflow dispatch can enable it.

GitHub Actions runs the experiment weekly, on manual request, and when its own
contract changes. It publishes the complete directory for 30 days, including
`report.json`, all twelve raw iperf JSON documents, both TCPCC event streams and
diagnostics, ping output, topology state, and before/after qdisc counters.

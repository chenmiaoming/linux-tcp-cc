# M11 constrained-CPU packet path

M11 targets small OpenVZ-style hosts where one available CPU is weaker than a
typical CI core. It keeps one hosted `vmlinux`, one TUN queue, one public
endpoint, and the existing single-owner bridge. It does not add SMP, a worker
pool, per-flow threads, or a periodic poll interval.

## M11.1: measured CPU and wakeup contract

The capacity driver records process CPU ticks, voluntary and involuntary
context switches, read/write syscall counts, host I/O bytes, RSS, threads, and
file descriptors. Its active probe reports CPU seconds per GiB for repeated
small bidirectional transfers. Long idle observations run both before public
flows and with the maximum requested connection stage established. The larger
of host read syscalls and voluntary context switches is reported as a
conservative host-wakeup proxy; it catches a timer-driven loop even when that
loop happens to use little CPU.

The `M11 CPU efficiency` CI matrix places only the hosted `vmlinux` in a cgroup
v2 leaf with 25% or 50% of one CPU. Each case boots with the 128-MiB default,
holds 8,192 connections, runs 128 small-packet rounds over 64 active flows, and
observes both zero-flow and loaded idle periods for 30 seconds. Each idle period
must average no more than 1% of one core and no more than five host wakeups per
second. The CPU matrix stops after its load, idle, service-drain, and clean
shutdown checks; it does not duplicate the asynchronous RSS-reclaim, reuse, or
multi-round stability gates. Those remain strict in the independent 16,384-flow
M10 lifecycle job. Raw JSON and the hosted log remain artifacts so later
optimizations can compare CPU, context switches, syscalls, and throughput
without replacing evidence with one synthetic score.

Existing hosted lossless delayed-path, transoceanic impairment, 16,384-flow
capacity, IPv6, and firewall jobs remain the throughput and correctness gates.
The constrained CPU job complements them; it does not reinterpret their
results. The former KVM/virtme-ng native parity workflow was removed because
GitHub-hosted runners do not reliably expose `/dev/kvm`; the non-KVM
transoceanic suite remains the native CUBIC/BBR performance comparison.

## M11.2: coalesced TX wakeups

The old L3 adapter called `complete()` for every queued skb. Because a
completion retains one credit per call while the TX thread drained the whole
queue at once, a burst could leave stale credits and cause later empty loop
iterations. The M11 queue wakes its waitqueue only on an empty-to-nonempty
transition. Queue state is the condition, so wake credits cannot accumulate.

Shutdown, host readiness, and netdevice TX all wake the same condition wait.
The final packet-pump telemetry records queue wakeups and empty rounds. CI
requires zero empty rounds and requires queue wakeups not to exceed successfully
transmitted packets.

## M11.3: one budgeted L3 packet pump

Separate `tcpcc-l3-rx` and `tcpcc-l3-tx` kthreads are replaced by one
`tcpcc-l3-io` owner. Each scheduling round processes at most 64 RX packets and
64 TX packets. If RX reaches its budget before draining the edge, it marks
itself ready and yields before continuing, so traffic in one direction cannot
monopolize the single vCPU.

TX retains the current skb across TUN backpressure. A write returning `EAGAIN`
temporarily arms `EPOLLOUT`, but the packet pump remains available for RX. On a
writable IRQ it removes write interest before retrying. Permanently armed
`EPOLLOUT`, timer retries, and busy scanning remain forbidden.

The shutdown path first marks the adapter stopping, removes host readiness,
disables its IRQ, stops the netdevice queue, wakes the one packet pump, and then
reaps queued packets. The final log reports RX/TX packets, pump rounds, IRQ and
queue wakeups, writable waits, and budget yields.

The production config also uses `CONFIG_NO_HZ_IDLE=y`. The hosted architecture
already supplies a one-shot clockevent and enters its blocking epoll dispatcher
from `arch_cpu_idle()`, so the generic idle-dynticks code can disarm the former
100 Hz scheduler tick while no work is runnable. CI explicitly rejects
`CONFIG_HZ_PERIODIC=y` and the long-idle wakeup ceiling prevents that polling
behavior from returning unnoticed.

## Release independence

M11 is an ordinary product change and must not publish a new binary Release.
The Release workflow is eligible only when the exact validated `6.18.y` commit
changes `upstream/linux.env` relative to its first parent. Product changes
accumulate on the branch and first ship in the next sequential upstream Linux
6.18.y update. The trigger contract has a repository test covering both an
ordinary commit and an LTS pin change.

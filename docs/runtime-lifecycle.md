# Runtime, process, and shutdown lifecycle

This document records the **current production runtime lifecycle**. It complements
[`../ARCHITECTURE.md`](../ARCHITECTURE.md): the architecture document defines
ownership and product boundaries, while this file describes how the native
supervisor and hosted Linux process start, handle signals, finalize boot, and
shut down.

## Process model

The installed `tcpcc` command is the native C supervisor. It owns host-side
lifecycle and resource rollback; the hosted `ARCH=tcpcc` Linux image owns the
public TCP listener, packet processing, congestion control, and stream bridge.

The supervisor starts the hosted image with `fork()`/`execv()`. Before `execv()`
the child:

- calls `setsid()` so terminal-generated signals sent to the supervisor's
  foreground process group do not directly control the hosted kernel;
- installs `PR_SET_PDEATHSIG=SIGKILL`, so an unexpected supervisor death cannot
  leave the hosted kernel running without its resource owner;
- maps the fixed-record control pipes to stdin/stdout;
- passes the inherited TUN queue as fd 3; and
- closes unrelated descriptors before `execv()`.

The supervisor observes child death through `pidfd_open()` when available. On
older hosts it falls back to `EPOLLHUP` on a duplicated control-response pipe,
so child monitoring remains event-driven without a polling helper thread.

## SIGINT and SIGTERM

`SIGINT` and `SIGTERM` are blocked by the supervisor before the hosted process is
started. They are consumed through a nonblocking `signalfd` registered in the
same epoll loop that watches hosted-process death.

This avoids an asynchronous signal handler interrupting TUN/firewall/control
cleanup at an arbitrary instruction. A shutdown signal instead becomes an
ordinary runtime event:

```text
SIGINT / SIGTERM
        |
        v
blocked signal mask
        |
        v
signalfd readable
        |
        v
epoll wakeup
        |
        v
record requested signal
        |
        v
SERVICE_DRAIN
        |
        | wait up to --shutdown-grace-period
        v
SERVICE_STOP
        |
        v
wait for hosted kernel exit
        |
        v
remove exact firewall resource
        |
        v
close nonpersistent TUN
```

The default drain grace period is five seconds. A drain timeout is reported but
does not abandon cleanup: the supervisor proceeds to `SERVICE_STOP` and tears
down the owned resources.

A clean signal-driven shutdown currently exits with status 0 and records the
received signal in the final `tcpcc.runtime.v1` `stopped` event. This is a
deliberate service-style success convention rather than shell-style `128 +
signal` exit status.

Because the signal mask is established before `fork()`, the hosted image also
inherits blocked `SIGINT`/`SIGTERM`. Combined with `setsid()`, Ctrl+C is therefore
owned by the supervisor rather than independently terminating both processes.

## SIGPIPE

The installed entry point sets `SIGPIPE` to `SIG_IGN` before argument parsing or
runtime startup.

This is required for transactional teardown. Runtime/status output is commonly
piped through `tee`, `logger`, or another consumer. If that consumer disappears,
a shutdown log write must not terminate the supervisor before it removes the
owned firewall state and closes the TUN queue. With `SIGPIPE` ignored, failed
writes report `EPIPE` and the cleanup path can continue.

The ignored disposition is currently inherited by the hosted image across
`fork()`/`execv()`. The hosted runtime does not rely on default SIGPIPE process
termination for control-pipe failure; control and child lifecycle are handled
explicitly. If this inheritance policy is changed later, it should be treated as
a process-boundary change and regression-tested rather than altered implicitly.

## Failure cleanup

The normal shutdown path asks the hosted service to drain and stop cleanly. If
that path fails while the hosted process is still alive, supervisor cleanup is
more aggressive:

1. attempt `SERVICE_STOP` when a service handle exists;
2. send `SIGKILL` to the hosted process;
3. close control channels and reap the child;
4. remove the exact instance-owned firewall resource; and
5. close the TUN fd, deleting the exclusive nonpersistent interface.

`SIGKILL` delivered to the supervisor itself cannot run userspace cleanup. The
firewall ownership markers therefore exist so the next startup can detect and
report stale state instead of guessing that an unrelated rule may be deleted.

## Hosted Linux boot finalization

Before PR #127, the production control path blocked for the entire service
lifetime inside a synchronous late initcall. Linux therefore never completed
its normal `kernel_init()` finalization while tcpcc was serving traffic:
`free_initmem()`, the transition to `SYSTEM_RUNNING`, and the end of in-kernel
RCU boot were all deferred until shutdown.

The current lifecycle separates one-time control initialization from the
long-running runtime:

```text
late_initcall_sync(tcpcc_control_init)
        |
        | initialize IRQ/event/control worker
        v
      return
        |
        v
kernel_init_freeable() completes
        |
        v
free_initmem()
        |
        | ARCH=tcpcc: munmap host ELF __init_begin..__init_end
        v
SYSTEM_RUNNING
        |
        v
rcu_end_inkernel_boot()
        |
        v
arch_post_kernel_init()
        |
        | publish control-ready marker
        v
long-lived hosted runtime
```

`ARCH=tcpcc` cannot use generic `free_initmem_default()` because its host ELF
mapping is separate from the anonymous `tcpcc_physmem` guest-RAM arena and
`virt_to_page()` is defined for the latter. The architecture therefore unmaps
the page-aligned init-image range through the host syscall boundary. The current
Linux 6.18.51 image reclaims 96 KiB this way before the ready marker is emitted.

The linker currently places `PERCPU_SECTION` inside the discardable init bounds,
while the resolved production `.data..percpu` section is zero bytes. Final-link
validation hard-fails if that invariant changes, preventing a future config from
silently placing live per-CPU state inside the unmapped range.

## Readiness invariant

The supervisor must not submit normal control requests merely because the
hosted process exists. Hosted readiness is published only after Linux has
finished boot finalization and reclaimed its init mapping. This gives the
operator-visible `ready` state a stronger meaning:

- control worker initialized;
- hosted kernel boot finalized;
- init-only host mapping reclaimed;
- kernel state is `SYSTEM_RUNNING`; and
- normal runtime control/service operations may begin.

This ordering is part of the runtime contract and should remain covered by the
hosted bootstrap/log validation when lifecycle code changes.

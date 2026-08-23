// SPDX-License-Identifier: GPL-2.0-only
#include <linux/clockchips.h>
#include <linux/clocksource.h>
#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irqflags.h>
#include <linux/panic.h>
#include <linux/printk.h>
#include <linux/timekeeping.h>
#include <asm/host.h>

#define TCPCC_CLOCK_HZ              NSEC_PER_SEC
#define TCPCC_TIMER_MIN_DELTA_NS    1000UL
#define TCPCC_TIMER_MAX_DELTA_NS    (60UL * NSEC_PER_SEC)
#define TCPCC_TIMER_TEST_DELAY_NS   (1ULL * NSEC_PER_MSEC)
#define TCPCC_TIMER_CANCEL_DELAY_NS (20ULL * NSEC_PER_MSEC)
#define TCPCC_TIMER_TEST_ROUNDS     32
#define TCPCC_TIMER_MAX_DISPATCHES  64

static int tcpcc_timer_fd = -1;
static unsigned int tcpcc_test_fired;
static u64 tcpcc_test_fired_ns;

static u64 tcpcc_clocksource_read(struct clocksource *cs)
{
	return tcpcc_host_monotonic_ns();
}

static struct clocksource tcpcc_clocksource = {
	.name = "tcpcc-host-monotonic",
	.rating = 400,
	.read = tcpcc_clocksource_read,
	.mask = CLOCKSOURCE_MASK(64),
	.flags = CLOCK_SOURCE_IS_CONTINUOUS,
};

/*
 * timekeeping_init() asks the architecture for its default clocksource before
 * time_init() runs. Override the weak jiffies fallback so Linux monotonic time
 * is host CLOCK_MONOTONIC-backed from the first timekeeper setup, rather than
 * switching clocks later in boot.
 */
struct clocksource *__init clocksource_default_clock(void)
{
	static bool registered;
	int ret;

	if (!registered) {
		ret = clocksource_register_hz(&tcpcc_clocksource, TCPCC_CLOCK_HZ);
		if (ret)
			panic("tcpcc: host monotonic clocksource registration failed: %d",
			      ret);
		registered = true;
		pr_notice("tcpcc: M3.2 host monotonic clocksource active\n");
	}

	return &tcpcc_clocksource;
}

static int tcpcc_clockevent_shutdown(struct clock_event_device *evt)
{
	return tcpcc_host_timer_cancel(tcpcc_timer_fd);
}

static int tcpcc_clockevent_oneshot(struct clock_event_device *evt)
{
	return tcpcc_host_timer_cancel(tcpcc_timer_fd);
}

static int tcpcc_clockevent_next(unsigned long delta,
				 struct clock_event_device *evt)
{
	/* timerfd value zero means disarm, never a zero-length event. */
	if (!delta)
		delta = 1;
	return tcpcc_host_timer_arm(tcpcc_timer_fd, delta);
}

static struct clock_event_device tcpcc_clockevent = {
	.name = "tcpcc-host-oneshot",
	.rating = 400,
	.features = CLOCK_EVT_FEAT_ONESHOT,
	.set_state_shutdown = tcpcc_clockevent_shutdown,
	.set_state_oneshot = tcpcc_clockevent_oneshot,
	.set_next_event = tcpcc_clockevent_next,
	.cpumask = cpu_possible_mask,
};

/*
 * timerfd expiry is level-like pending state in the host. The one Linux vCPU
 * blocks only at an explicit safe point, then enters the normal Linux
 * clockevent handler with local IRQs masked and hardirq accounting active.
 * M3.4/#27 will fold this fd into the general host IRQ/softirq event loop.
 */
static void tcpcc_timer_wait_and_dispatch(void)
{
	u64 expirations;
	unsigned long flags;
	int ret;

	if (irqs_disabled())
		panic("tcpcc: timer dispatch attempted with local IRQs disabled");

	ret = tcpcc_host_timer_wait(tcpcc_timer_fd, &expirations);
	if (ret)
		panic("tcpcc: host timer wait failed: %d", ret);
	if (!expirations)
		panic("tcpcc: host timer wakeup without an expiration");
	if (!tcpcc_clockevent.event_handler)
		panic("tcpcc: clockevent fired before handler installation");

	local_irq_save(flags);
	irq_enter();
	tcpcc_clockevent.event_handler(&tcpcc_clockevent);
	irq_exit();
	local_irq_restore(flags);
}

void tcpcc_host_idle_wait(void)
{
	/*
	 * default_idle_call() reaches arch_cpu_idle() with local IRQs disabled.
	 * No host callback can race this transition: expiration merely becomes
	 * readable on timerfd. Enable the Linux IRQ state first, then consume and
	 * synchronously dispatch that pending event.
	 */
	if (!irqs_disabled())
		panic("tcpcc: hosted idle wait entered with local IRQs enabled");

	local_irq_enable();
	tcpcc_timer_wait_and_dispatch();
}

static enum hrtimer_restart tcpcc_timer_test_callback(struct hrtimer *timer)
{
	tcpcc_test_fired_ns = ktime_get_ns();
	tcpcc_test_fired++;
	return HRTIMER_NORESTART;
}

static void __init tcpcc_timer_selftest(void)
{
	struct hrtimer timer;
	u64 clock_start, clock_end, expected, late, worst_late = 0;
	unsigned int before, dispatches, round;
	int ret;

	hrtimer_setup(&timer, tcpcc_timer_test_callback, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL);

	/*
	 * The clockevent is registered while early boot IRQs are disabled. Its
	 * first periodic-emulation event is therefore already pending (or armed)
	 * when late_time_init runs. Deliver it now so hrtimer_run_queues() can
	 * perform Linux's normal transition into high-resolution mode.
	 */
	clock_start = ktime_get_ns();
	for (dispatches = 0;
	     dispatches < TCPCC_TIMER_MAX_DISPATCHES &&
	     !hrtimer_is_hres_active(&timer);
	     dispatches++)
		tcpcc_timer_wait_and_dispatch();

	if (!hrtimer_is_hres_active(&timer))
		panic("tcpcc: Linux hrtimer core did not enter high-resolution mode");

	clock_end = ktime_get_ns();
	if (clock_end <= clock_start)
		panic("tcpcc: host monotonic time did not advance");

	/*
	 * Exercise the Linux hrtimer -> clockevent -> timerfd path repeatedly.
	 * Each round first arms a later timer and cancels it, then rearms the same
	 * hrtimer for a 1ms expiration. Exactly one callback must be observed and
	 * it must not run before its requested host-monotonic deadline.
	 */
	for (round = 0; round < TCPCC_TIMER_TEST_ROUNDS; round++) {
		before = tcpcc_test_fired;
		hrtimer_start(&timer, ns_to_ktime(TCPCC_TIMER_CANCEL_DELAY_NS),
			      HRTIMER_MODE_REL);
		ret = hrtimer_cancel(&timer);
		if (ret != 1)
			panic("tcpcc: hrtimer cancel round %u returned %d", round, ret);

		expected = ktime_get_ns() + TCPCC_TIMER_TEST_DELAY_NS;
		hrtimer_start(&timer, ns_to_ktime(TCPCC_TIMER_TEST_DELAY_NS),
			      HRTIMER_MODE_REL);

		for (dispatches = 0;
		     dispatches < TCPCC_TIMER_MAX_DISPATCHES &&
		     tcpcc_test_fired == before;
		     dispatches++)
			tcpcc_timer_wait_and_dispatch();

		if (tcpcc_test_fired != before + 1)
			panic("tcpcc: hrtimer round %u fired %u times",
			      round, tcpcc_test_fired - before);
		if (tcpcc_test_fired_ns < expected)
			panic("tcpcc: hrtimer round %u fired early by %llu ns",
			      round,
			      (unsigned long long)(expected - tcpcc_test_fired_ns));

		late = tcpcc_test_fired_ns - expected;
		if (late > worst_late)
			worst_late = late;
	}

	if (hrtimer_cancel(&timer))
		panic("tcpcc: completed hrtimer remained queued");

	pr_notice("tcpcc: M3.2 one-shot hrtimer stress passed (%u rounds, worst lateness %llu ns)\n",
		  TCPCC_TIMER_TEST_ROUNDS, (unsigned long long)worst_late);
}

void __init time_init(void)
{
	tcpcc_timer_fd = tcpcc_host_timer_create();
	if (tcpcc_timer_fd < 0)
		panic("tcpcc: timerfd_create(CLOCK_MONOTONIC) failed: %d",
		      tcpcc_timer_fd);

	clockevents_config_and_register(&tcpcc_clockevent, TCPCC_CLOCK_HZ,
					TCPCC_TIMER_MIN_DELTA_NS,
					TCPCC_TIMER_MAX_DELTA_NS);

	pr_notice("tcpcc: M3.2 host one-shot clockevent registered\n");
	late_time_init = tcpcc_timer_selftest;
}

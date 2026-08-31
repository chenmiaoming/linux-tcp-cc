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
#include <asm/irq_regs.h>
#include <asm/ptrace.h>
#include <asm/tcpcc_compat.h>

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
 * Consume one pending timerfd expiration and enter the normal Linux clockevent
 * path. M3.4 calls this from the shared host event dispatcher; the M3.2 early
 * selftest also invokes it directly before the scheduler event loop is active.
 */
void tcpcc_timer_dispatch(void)
{
	struct pt_regs regs = { 0 };
	struct pt_regs *old_regs;
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

	/*
	 * High-resolution tick handling only runs update_process_times() when an
	 * IRQ register frame is published. Model a real architecture IRQ entry so
	 * timer-wheel, scheduler and softirq semantics remain generic Linux code.
	 */
	local_irq_save(flags);
	old_regs = set_irq_regs(&regs);
	irq_enter();
	tcpcc_clockevent.event_handler(&tcpcc_clockevent);
	irq_exit();
	set_irq_regs(old_regs);
	local_irq_restore(flags);
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

	clock_start = ktime_get_ns();
	for (dispatches = 0;
	     dispatches < TCPCC_TIMER_MAX_DISPATCHES &&
	     !tcpcc_compat_hrtimer_is_highres();
	     dispatches++)
		tcpcc_timer_dispatch();

	if (!tcpcc_compat_hrtimer_is_highres())
		panic("tcpcc: Linux hrtimer core did not enter high-resolution mode");

	clock_end = ktime_get_ns();
	if (clock_end <= clock_start)
		panic("tcpcc: host monotonic time did not advance");

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
			tcpcc_timer_dispatch();

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
	int ret;

	tcpcc_timer_fd = tcpcc_host_timer_create();
	if (tcpcc_timer_fd < 0)
		panic("tcpcc: timerfd_create(CLOCK_MONOTONIC) failed: %d",
		      tcpcc_timer_fd);

	ret = tcpcc_host_event_add(tcpcc_timer_fd, TCPCC_HOST_EVENT_TIMER);
	if (ret)
		panic("tcpcc: failed to register timerfd with host event loop: %d",
		      ret);

	clockevents_config_and_register(&tcpcc_clockevent, TCPCC_CLOCK_HZ,
					TCPCC_TIMER_MIN_DELTA_NS,
					TCPCC_TIMER_MAX_DELTA_NS);

	pr_notice("tcpcc: M3.2 host one-shot clockevent registered\n");
	late_time_init = tcpcc_timer_selftest;
}

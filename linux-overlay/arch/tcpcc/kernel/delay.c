// SPDX-License-Identifier: GPL-2.0-only
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/math64.h>
#include <linux/types.h>
#include <asm/host.h>
#include <asm/processor.h>

void __delay(unsigned long loops)
{
	while (loops--)
		cpu_relax();
}

/*
 * tcpcc has no asynchronous timer entry before the idle/event path exists, so
 * the generic jiffies-based delay calibration cannot make progress during
 * early boot. Measure a bounded raw loop against the already-established host
 * CLOCK_MONOTONIC clocksource instead and return loops-per-jiffy directly.
 */
unsigned long calibrate_delay_is_known(void)
{
	const unsigned long probe_loops = 1UL << 20;
	u64 start, end, elapsed, lpj;

	start = tcpcc_host_monotonic_ns();
	__delay(probe_loops);
	end = tcpcc_host_monotonic_ns();
	elapsed = end - start;
	if (!elapsed)
		return 1UL << 12;

	lpj = div64_u64((u64)probe_loops * (1000000000ULL / HZ), elapsed);
	if (!lpj)
		lpj = 1;

	return (unsigned long)lpj;
}

void __const_udelay(unsigned long xloops)
{
	u64 loops = (u64)xloops * loops_per_jiffy * HZ;

	__delay(loops >> 32);
}

void __udelay(unsigned long usecs)
{
	__const_udelay(usecs * 0x10c7UL);
}

void __ndelay(unsigned long nsecs)
{
	__const_udelay(nsecs * 0x5UL);
}

// SPDX-License-Identifier: GPL-2.0-only
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/types.h>
#include <asm/processor.h>

/*
 * Linux's generic delay calibration supplies loops_per_jiffy.  Keep the
 * standard architecture delay ABI available at link time; M3 may replace the
 * raw loop with a host-clock implementation if calibration jitter is too high.
 */
void __delay(unsigned long loops)
{
	while (loops--)
		cpu_relax();
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

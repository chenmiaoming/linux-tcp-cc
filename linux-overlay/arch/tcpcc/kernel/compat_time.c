// SPDX-License-Identifier: GPL-2.0-only
#include <linux/hrtimer.h>
#include <asm/tcpcc_compat.h>

bool tcpcc_compat_hrtimer_is_highres(void)
{
	/* TCPCC is single-CPU, so the global resolution reflects its CPU base. */
	return IS_ENABLED(CONFIG_HIGH_RES_TIMERS) && hrtimer_resolution == 1;
}

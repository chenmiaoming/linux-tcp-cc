// SPDX-License-Identifier: GPL-2.0-only
#include <linux/seq_file.h>

static void *tcpcc_cpuinfo_start(struct seq_file *m, loff_t *pos)
{
	return *pos == 0 ? (void *)1 : NULL;
}

static void *tcpcc_cpuinfo_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void tcpcc_cpuinfo_stop(struct seq_file *m, void *v)
{
}

static int tcpcc_cpuinfo_show(struct seq_file *m, void *v)
{
	seq_puts(m, "processor\t: 0\nmodel name\t: linux-tcp-cc hosted vCPU\n");
	return 0;
}

const struct seq_operations cpuinfo_op = {
	.start = tcpcc_cpuinfo_start,
	.next = tcpcc_cpuinfo_next,
	.stop = tcpcc_cpuinfo_stop,
	.show = tcpcc_cpuinfo_show,
};

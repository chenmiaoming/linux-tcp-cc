// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/workqueue.h>
#include <linux/page_reporting.h>
#include <linux/printk.h>
#include <linux/scatterlist.h>
#include <asm/host.h>
#include <asm/page.h>
#include <asm/reclaim.h>

/* Avoid order-0 syscall churn and bound each host advisory range to 16 MiB. */
#define TCPCC_RECLAIM_MIN_ORDER		3U
#define TCPCC_RECLAIM_MAX_RANGE_BYTES	(16UL * 1024UL * 1024UL)

struct tcpcc_reclaim_range {
	unsigned long start;
	unsigned long length;
};

static struct page_reporting_dev_info tcpcc_reclaim_dev;
static struct work_struct tcpcc_reclaim_disable_work;
static struct tcpcc_control_reclaim_stats tcpcc_reclaim_stats = {
	.state = TCPCC_CONTROL_RECLAIM_STARTING,
	.minimum_order = TCPCC_RECLAIM_MIN_ORDER,
	.maximum_range_bytes = TCPCC_RECLAIM_MAX_RANGE_BYTES,
};

static void tcpcc_reclaim_disable(struct work_struct *work)
{
	(void)work;
	page_reporting_unregister(&tcpcc_reclaim_dev);
}

static int tcpcc_reclaim_fail(int error, u64 bytes)
{
	if (!tcpcc_reclaim_stats.advisory_failures) {
		tcpcc_reclaim_stats.advisory_failures = 1;
		tcpcc_reclaim_stats.last_error = error;
		tcpcc_reclaim_stats.state =
			(error == -ENOSYS || error == -EINVAL) ?
			TCPCC_CONTROL_RECLAIM_UNSUPPORTED :
			TCPCC_CONTROL_RECLAIM_FAILED;
		pr_warn("tcpcc: M10.3 host page reclaim disabled: %d\n", error);
		schedule_work(&tcpcc_reclaim_disable_work);
	}
	tcpcc_reclaim_stats.failed_bytes += bytes;
	return error;
}

static void tcpcc_reclaim_sort(struct tcpcc_reclaim_range *ranges,
			       unsigned int count)
{
	unsigned int index;

	(void)prdev;

	for (index = 1; index < count; index++) {
		struct tcpcc_reclaim_range value = ranges[index];
		unsigned int cursor = index;

		while (cursor && ranges[cursor - 1].start > value.start) {
			ranges[cursor] = ranges[cursor - 1];
			cursor--;
		}
		ranges[cursor] = value;
	}
}

static int tcpcc_reclaim_one_range(unsigned long start, unsigned long length)
{
	while (length) {
		unsigned long chunk = min(length,
					  TCPCC_RECLAIM_MAX_RANGE_BYTES);
		int ret;

		tcpcc_reclaim_stats.ranges++;
		ret = tcpcc_host_discard_pages((void *)start, chunk);
		if (ret)
			return tcpcc_reclaim_fail(ret, length);
		tcpcc_reclaim_stats.successful_discard_bytes += chunk;
		start += chunk;
		length -= chunk;
	}

	return 0;
}

static int tcpcc_reclaim_report(struct page_reporting_dev_info *prdev,
				struct scatterlist *sgl,
				unsigned int nents)
{
	struct tcpcc_reclaim_range ranges[PAGE_REPORTING_CAPACITY];
	struct scatterlist *sg;
	u64 total = 0;
	unsigned int count = 0;
	unsigned int index;

	if (!nents || nents > ARRAY_SIZE(ranges))
		return tcpcc_reclaim_fail(-EINVAL, 0);

	for_each_sg(sgl, sg, nents, index) {
		struct page *page = sg_page(sg);
		unsigned long pfn;
		unsigned long pages;

		if (!page || sg->offset || !sg->length ||
		    !IS_ALIGNED(sg->length, PAGE_SIZE))
			return tcpcc_reclaim_fail(-EINVAL, total);
		pfn = page_to_pfn(page);
		pages = sg->length >> PAGE_SHIFT;
		/* PFN zero and every non-managed/reserved range stay unreachable. */
		if (!pfn || pfn >= max_pfn || pages > max_pfn - pfn)
			return tcpcc_reclaim_fail(-ERANGE, total);

		ranges[count].start = (unsigned long)pfn_to_virt(pfn);
		ranges[count].length = sg->length;
		total += sg->length;
		count++;
	}

	tcpcc_reclaim_stats.batches++;
	tcpcc_reclaim_stats.reported_bytes += total;
	tcpcc_reclaim_sort(ranges, count);

	for (index = 0; index < count; index++) {
		unsigned long start = ranges[index].start;
		unsigned long length = ranges[index].length;

		while (index + 1 < count &&
		       start + length == ranges[index + 1].start &&
		       length <= ULONG_MAX - ranges[index + 1].length) {
			length += ranges[++index].length;
		}
		if (tcpcc_reclaim_one_range(start, length))
			return tcpcc_reclaim_stats.last_error;
	}

	return 0;
}

void tcpcc_reclaim_get_stats(struct tcpcc_control_reclaim_stats *stats)
{
	stats->reported_bytes = READ_ONCE(tcpcc_reclaim_stats.reported_bytes);
	stats->successful_discard_bytes =
		READ_ONCE(tcpcc_reclaim_stats.successful_discard_bytes);
	stats->batches = READ_ONCE(tcpcc_reclaim_stats.batches);
	stats->ranges = READ_ONCE(tcpcc_reclaim_stats.ranges);
	stats->failed_bytes = READ_ONCE(tcpcc_reclaim_stats.failed_bytes);
	stats->advisory_failures =
		READ_ONCE(tcpcc_reclaim_stats.advisory_failures);
	stats->state = READ_ONCE(tcpcc_reclaim_stats.state);
	stats->last_error = READ_ONCE(tcpcc_reclaim_stats.last_error);
	stats->minimum_order = TCPCC_RECLAIM_MIN_ORDER;
	stats->maximum_range_bytes = TCPCC_RECLAIM_MAX_RANGE_BYTES;
}

static int __init tcpcc_reclaim_init(void)
{
	int ret;

	BUILD_BUG_ON(TCPCC_RECLAIM_MIN_ORDER > MAX_PAGE_ORDER);
	BUILD_BUG_ON(sizeof(struct tcpcc_control_reclaim_stats) != 72);
	INIT_WORK(&tcpcc_reclaim_disable_work, tcpcc_reclaim_disable);
	tcpcc_reclaim_dev.report = tcpcc_reclaim_report;
	tcpcc_reclaim_dev.order = TCPCC_RECLAIM_MIN_ORDER;
	ret = page_reporting_register(&tcpcc_reclaim_dev);
	if (ret) {
		tcpcc_reclaim_stats.last_error = ret;
		tcpcc_reclaim_stats.advisory_failures = 1;
		tcpcc_reclaim_stats.state = TCPCC_CONTROL_RECLAIM_FAILED;
		pr_warn("tcpcc: M10.3 page reporting unavailable: %d\n", ret);
		return 0;
	}

	tcpcc_reclaim_stats.state = TCPCC_CONTROL_RECLAIM_ACTIVE;
	pr_notice("tcpcc: M10.3 batched guest-free page reclaim active, order >= %u\n",
		  TCPCC_RECLAIM_MIN_ORDER);
	return 0;
}
subsys_initcall(tcpcc_reclaim_init);

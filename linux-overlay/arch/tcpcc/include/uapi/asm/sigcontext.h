/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_TCPCC_SIGCONTEXT_H
#define _UAPI_ASM_TCPCC_SIGCONTEXT_H

/*
 * Minimal hosted-kernel signal context for the M2 bring-up. tcpcc does not
 * expose a userspace register ABI yet; this mirrors the narrow shape used by
 * LKL until task/context semantics are implemented in a later milestone.
 */
struct pt_regs {
	void *irq_data;
};

struct sigcontext {
	struct pt_regs regs;
	unsigned long oldmask;
};

#endif

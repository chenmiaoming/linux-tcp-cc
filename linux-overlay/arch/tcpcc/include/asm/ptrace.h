/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_PTRACE_H
#define _ASM_TCPCC_PTRACE_H

/*
 * tcpcc executes Linux networking code in kernel context only. There is no
 * guest userspace privilege level in the initial architecture, so pt_regs is
 * an internal execution-frame placeholder and user_mode() is always false.
 * The host bootstrap/context-switch implementation may extend this structure
 * without creating a UAPI commitment.
 */
struct pt_regs {
	unsigned long reserved;
};

#define user_mode(regs) (0)

#endif /* _ASM_TCPCC_PTRACE_H */

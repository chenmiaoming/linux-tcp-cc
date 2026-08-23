/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_TCPCC_SIGCONTEXT_H
#define _UAPI_ASM_TCPCC_SIGCONTEXT_H

/*
 * tcpcc currently has no guest userspace execution ABI. Keep the mandatory
 * UAPI signal-context type deliberately opaque until such an ABI is designed;
 * kernel pt_regs belongs to the internal asm/ptrace.h contract instead.
 */
struct sigcontext {
	unsigned long reserved;
};

#endif /* _UAPI_ASM_TCPCC_SIGCONTEXT_H */

/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_TCPCC_PTRACE_H
#define _UAPI_ASM_TCPCC_PTRACE_H

/*
 * The initial tcpcc userspace port does not expose an architecture register
 * ABI yet. This header exists because Linux 6.18 marks asm/ptrace.h as a
 * mandatory UAPI architecture header. Register state will be defined when
 * task/signal context switching is implemented in a later milestone.
 */

#endif

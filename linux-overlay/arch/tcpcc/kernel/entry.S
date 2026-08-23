/* SPDX-License-Identifier: GPL-2.0-only */

	.text
	.globl tcpcc_host_start
	.type tcpcc_host_start,@function
tcpcc_host_start:
	/* Linux/x86-64 process entry provides a valid userspace stack. */
	cld
	xorq %rbp, %rbp
	andq $-16, %rsp
	call start_kernel

	/* start_kernel() is __noreturn; make an ABI violation visible. */
	movl $127, %edi
	call tcpcc_host_exit
1:
	pause
	jmp 1b
	.size tcpcc_host_start, .-tcpcc_host_start

	.section .note.GNU-stack,"",@progbits

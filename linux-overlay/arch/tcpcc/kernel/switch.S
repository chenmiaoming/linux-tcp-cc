/* SPDX-License-Identifier: GPL-2.0-only */

	.text
	.p2align 4
	.globl tcpcc_switch_context
	.type tcpcc_switch_context, @function
/*
 * void tcpcc_switch_context(unsigned long *prev_sp, unsigned long next_sp)
 *
 * The hosted image is an x86-64 Linux process and follows the SysV ABI. Save
 * precisely the callee-saved general registers on the inactive Linux kernel
 * stack, publish that stack pointer, load the next task's saved stack, and
 * return through the continuation stored on that stack.
 */
tcpcc_switch_context:
	pushq %rbx
	pushq %rbp
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

	movq %rsp, (%rdi)
	movq %rsi, %rsp

	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbp
	popq %rbx
	ret
	.size tcpcc_switch_context, .-tcpcc_switch_context

	.section .note.GNU-stack,"",@progbits

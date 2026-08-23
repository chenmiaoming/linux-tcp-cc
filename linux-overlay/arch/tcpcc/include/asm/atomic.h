/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_TCPCC_ATOMIC_H
#define _ASM_TCPCC_ATOMIC_H

/*
 * tcpcc starts as a single-vCPU architecture. Reuse the generic UP atomic_t
 * implementation, which serializes read-modify-write operations against local
 * interrupt delivery. Linux 6.18 defines atomic64_t itself for CONFIG_64BIT,
 * so CONFIG_GENERIC_ATOMIC64 is not appropriate here: that fallback also
 * declares atomic64_t and conflicts with include/linux/types.h.
 */
#include <asm-generic/atomic.h>

/* atomic64_t itself comes from include/linux/types.h on 64-bit architectures;
 * the architecture still owns its static initializer. */
#define ATOMIC64_INIT(i) { (i) }

/*
 * Provide the corresponding 64-bit primitives using the same single-vCPU
 * serialization rule. Linux's atomic fallback discovers architecture
 * primitives with preprocessor defined() checks, so the implementation names
 * are kept private and explicitly exported through arch_atomic64_* macros,
 * matching the pattern used by asm-generic/atomic.h.
 *
 * Correctness of these operations depends on arch_local_irq_save/restore
 * serializing all kernel execution contexts for the virtual CPU. M2 only
 * establishes the architecture contract; the host IRQ implementation is a
 * later runtime milestone.
 */
#define TCPCC_ATOMIC64_OP(op, c_op)                                      \
static inline void tcpcc_atomic64_##op(s64 i, atomic64_t *v)              \
{                                                                         \
	unsigned long flags;                                                  \
	                                                                        \
	raw_local_irq_save(flags);                                            \
	v->counter = v->counter c_op i;                                       \
	raw_local_irq_restore(flags);                                         \
}

#define TCPCC_ATOMIC64_OP_RETURN(op, c_op)                               \
static inline s64 tcpcc_atomic64_##op##_return(s64 i, atomic64_t *v)      \
{                                                                         \
	unsigned long flags;                                                  \
	s64 ret;                                                              \
	                                                                        \
	raw_local_irq_save(flags);                                            \
	ret = (v->counter = v->counter c_op i);                               \
	raw_local_irq_restore(flags);                                         \
	                                                                        \
	return ret;                                                           \
}

#define TCPCC_ATOMIC64_FETCH_OP(op, c_op)                                \
static inline s64 tcpcc_atomic64_fetch_##op(s64 i, atomic64_t *v)         \
{                                                                         \
	unsigned long flags;                                                  \
	s64 ret;                                                              \
	                                                                        \
	raw_local_irq_save(flags);                                            \
	ret = v->counter;                                                     \
	v->counter = v->counter c_op i;                                       \
	raw_local_irq_restore(flags);                                         \
	                                                                        \
	return ret;                                                           \
}

static inline s64 tcpcc_atomic64_read(const atomic64_t *v)
{
	return READ_ONCE(v->counter);
}

static inline void tcpcc_atomic64_set(atomic64_t *v, s64 i)
{
	WRITE_ONCE(v->counter, i);
}

TCPCC_ATOMIC64_OP_RETURN(add, +)
TCPCC_ATOMIC64_OP_RETURN(sub, -)

TCPCC_ATOMIC64_FETCH_OP(add, +)
TCPCC_ATOMIC64_FETCH_OP(sub, -)
TCPCC_ATOMIC64_FETCH_OP(and, &)
TCPCC_ATOMIC64_FETCH_OP(or, |)
TCPCC_ATOMIC64_FETCH_OP(xor, ^)

TCPCC_ATOMIC64_OP(add, +)
TCPCC_ATOMIC64_OP(sub, -)
TCPCC_ATOMIC64_OP(and, &)
TCPCC_ATOMIC64_OP(or, |)
TCPCC_ATOMIC64_OP(xor, ^)

#define arch_atomic64_read tcpcc_atomic64_read
#define arch_atomic64_set tcpcc_atomic64_set
#define arch_atomic64_add tcpcc_atomic64_add
#define arch_atomic64_sub tcpcc_atomic64_sub
#define arch_atomic64_and tcpcc_atomic64_and
#define arch_atomic64_or tcpcc_atomic64_or
#define arch_atomic64_xor tcpcc_atomic64_xor
#define arch_atomic64_add_return tcpcc_atomic64_add_return
#define arch_atomic64_sub_return tcpcc_atomic64_sub_return
#define arch_atomic64_fetch_add tcpcc_atomic64_fetch_add
#define arch_atomic64_fetch_sub tcpcc_atomic64_fetch_sub
#define arch_atomic64_fetch_and tcpcc_atomic64_fetch_and
#define arch_atomic64_fetch_or tcpcc_atomic64_fetch_or
#define arch_atomic64_fetch_xor tcpcc_atomic64_fetch_xor

#undef TCPCC_ATOMIC64_FETCH_OP
#undef TCPCC_ATOMIC64_OP_RETURN
#undef TCPCC_ATOMIC64_OP

#endif /* _ASM_TCPCC_ATOMIC_H */

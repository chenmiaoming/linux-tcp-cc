# SPDX-License-Identifier: GPL-2.0-only

KBUILD_DEFCONFIG := defconfig
# tcpcc has no in-kernel stack unwinder.  Do not carry host-toolchain DWARF
# unwind metadata in the production executable.
KBUILD_CFLAGS += -fno-builtin -fPIC -fno-asynchronous-unwind-tables \
		 -fno-unwind-tables

core-y += arch/tcpcc/kernel/

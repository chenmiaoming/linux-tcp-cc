# SPDX-License-Identifier: GPL-2.0-only

obj-y += entry.o host.o console.o
obj-y += setup.o irq.o process.o time.o delay.o syscall.o cpuinfo.o

# Build the architecture linker script for the final vmlinux link.
always-$(KBUILD_BUILTIN) += vmlinux.lds

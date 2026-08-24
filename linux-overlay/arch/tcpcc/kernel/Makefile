# SPDX-License-Identifier: GPL-2.0-only

obj-y += entry.o host.o console.o
obj-y += setup.o irq.o process.o switch.o time.o delay.o syscall.o cpuinfo.o net.o l3net.o control.o

# Build the architecture linker script for the final vmlinux link.
always-$(KBUILD_BUILTIN) += vmlinux.lds

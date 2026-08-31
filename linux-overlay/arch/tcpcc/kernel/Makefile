# SPDX-License-Identifier: GPL-2.0-only

obj-y += entry.o host.o console.o
obj-y += setup.o compat_mm.o irq.o process.o switch.o time.o delay.o syscall.o cpuinfo.o
obj-y += net.o compat.o l3net.o bridge.o service.o control.o
obj-$(CONFIG_PAGE_REPORTING) += reclaim.o

# Build the architecture linker script for the final vmlinux link.
always-$(KBUILD_BUILTIN) += vmlinux.lds

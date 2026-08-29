# SPDX-License-Identifier: GPL-2.0-only

PREFIX ?= /usr/local
DESTDIR ?=
VMLINUX ?= .build/tcpcc-bootstrap-out/vmlinux
CC ?= cc
AR ?= ar

NATIVE_BUILD_DIR := .build/native
NATIVE_CPPFLAGS := -Ilinux-overlay/arch/tcpcc/include
NATIVE_CFLAGS := -O2 -Wall -Wextra -Werror -std=gnu11
NATIVE_LIBRARY := $(NATIVE_BUILD_DIR)/libtcpcc-native.a
NATIVE_OBJECTS := \
	$(NATIVE_BUILD_DIR)/tcpcc_control.o \
	$(NATIVE_BUILD_DIR)/tcpcc_event.o \
	$(NATIVE_BUILD_DIR)/tcpcc_process.o

PYTHON_MODULES := \
	tools/tcpcc_cli.py \
	tools/tcpcc_control.py \
	tools/tcpcc_host.py

.PHONY: install native-build native-check
install:
	test -x "$(VMLINUX)"
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -d "$(DESTDIR)$(PREFIX)/lib/tcpcc"
	install -d "$(DESTDIR)$(PREFIX)/libexec/tcpcc"
	install -m 0755 tcpcc "$(DESTDIR)$(PREFIX)/bin/tcpcc"
	install -m 0644 $(PYTHON_MODULES) "$(DESTDIR)$(PREFIX)/lib/tcpcc/"
	install -m 0755 "$(VMLINUX)" "$(DESTDIR)$(PREFIX)/libexec/tcpcc/vmlinux"

$(NATIVE_BUILD_DIR):
	mkdir -p $@

$(NATIVE_BUILD_DIR)/tcpcc_control.o: native/tcpcc_control.c \
		native/tcpcc_control.h \
		linux-overlay/arch/tcpcc/include/asm/tcpcc_control_abi.h | $(NATIVE_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(NATIVE_CPPFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) \
		-c -o $@ native/tcpcc_control.c

$(NATIVE_BUILD_DIR)/tcpcc_process.o: native/tcpcc_process.c \
		native/tcpcc_process.h native/tcpcc_control.h \
		linux-overlay/arch/tcpcc/include/asm/tcpcc_control_abi.h | $(NATIVE_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(NATIVE_CPPFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) \
		-c -o $@ native/tcpcc_process.c

$(NATIVE_BUILD_DIR)/tcpcc_event.o: native/tcpcc_event.c \
		native/tcpcc_event.h native/tcpcc_control.h | $(NATIVE_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(NATIVE_CPPFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) \
		-c -o $@ native/tcpcc_event.c

$(NATIVE_LIBRARY): $(NATIVE_OBJECTS)
	$(AR) rcs $@ $^

$(NATIVE_BUILD_DIR)/test-control: native/test_control.c $(NATIVE_LIBRARY)
	$(CC) $(CPPFLAGS) $(NATIVE_CPPFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) \
		-o $@ native/test_control.c $(NATIVE_LIBRARY)

$(NATIVE_BUILD_DIR)/test-hosted-child: native/test_hosted_child.c \
		native/tcpcc_process.h native/tcpcc_control.h \
		linux-overlay/arch/tcpcc/include/asm/tcpcc_control_abi.h | $(NATIVE_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(NATIVE_CPPFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) \
		-o $@ native/test_hosted_child.c

$(NATIVE_BUILD_DIR)/test-process: native/test_process.c \
		linux-overlay/arch/tcpcc/include/asm/host_mman.h $(NATIVE_LIBRARY)
	$(CC) $(CPPFLAGS) $(NATIVE_CPPFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) \
		-o $@ native/test_process.c $(NATIVE_LIBRARY)

$(NATIVE_BUILD_DIR)/test-event: native/test_event.c $(NATIVE_LIBRARY)
	$(CC) $(CPPFLAGS) $(NATIVE_CPPFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) \
		-o $@ native/test_event.c $(NATIVE_LIBRARY)

native-build: $(NATIVE_LIBRARY)

native-check: $(NATIVE_BUILD_DIR)/test-control \
		$(NATIVE_BUILD_DIR)/test-hosted-child \
		$(NATIVE_BUILD_DIR)/test-process \
		$(NATIVE_BUILD_DIR)/test-event
	$(NATIVE_BUILD_DIR)/test-control
	$(NATIVE_BUILD_DIR)/test-process $(NATIVE_BUILD_DIR)/test-hosted-child
	$(NATIVE_BUILD_DIR)/test-event

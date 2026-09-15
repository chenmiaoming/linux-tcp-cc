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
NATIVE_CLI := $(NATIVE_BUILD_DIR)/tcpcc
NATIVE_OBJECTS := \
	$(NATIVE_BUILD_DIR)/tcpcc_control.o \
	$(NATIVE_BUILD_DIR)/tcpcc_event.o \
	$(NATIVE_BUILD_DIR)/tcpcc_process.o
NATIVE_CLI_OBJECTS := \
	$(NATIVE_BUILD_DIR)/tcpcc_entry.o \
	$(NATIVE_BUILD_DIR)/tcpcc_cli.o \
	$(NATIVE_BUILD_DIR)/tcpcc_config.o
.PHONY: install native-build native-check release-package
install: $(NATIVE_CLI)
	test -x "$(VMLINUX)"
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -d "$(DESTDIR)$(PREFIX)/libexec/tcpcc"
	install -m 0755 "$(NATIVE_CLI)" "$(DESTDIR)$(PREFIX)/bin/tcpcc"
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

$(NATIVE_BUILD_DIR)/tcpcc_entry.o: native/tcpcc_entry.c \
		native/tcpcc_config.h native/tcpcc_process.h native/tcpcc_control.h | $(NATIVE_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(NATIVE_CPPFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) \
		-c -o $@ native/tcpcc_entry.c

$(NATIVE_BUILD_DIR)/tcpcc_config.o: native/tcpcc_config.c \
		native/tcpcc_config.h native/third_party/toml-c.h | $(NATIVE_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(NATIVE_CPPFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) \
		-c -o $@ native/tcpcc_config.c

$(NATIVE_BUILD_DIR)/tcpcc_cli.o: native/tcpcc_cli.c \
		native/tcpcc_control.h native/tcpcc_event.h native/tcpcc_process.h \
		linux-overlay/arch/tcpcc/include/asm/tcpcc_control_abi.h | $(NATIVE_BUILD_DIR)
	$(CC) $(CPPFLAGS) $(NATIVE_CPPFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) \
		-Dmain=tcpcc_cli_main -c -o $@ native/tcpcc_cli.c

$(NATIVE_LIBRARY): $(NATIVE_OBJECTS)
	$(AR) rcs $@ $^

$(NATIVE_CLI): $(NATIVE_CLI_OBJECTS) $(NATIVE_LIBRARY)
	$(CC) $(LDFLAGS) -o $@ $^ -ldl

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

$(NATIVE_BUILD_DIR)/test-sigpipe: native/test_sigpipe.c $(NATIVE_CLI)
	$(CC) $(CPPFLAGS) $(NATIVE_CPPFLAGS) $(CFLAGS) $(NATIVE_CFLAGS) \
		-o $@ native/test_sigpipe.c

native-build: $(NATIVE_LIBRARY) $(NATIVE_CLI)

native-check: $(NATIVE_BUILD_DIR)/test-control \
		$(NATIVE_BUILD_DIR)/test-hosted-child \
		$(NATIVE_BUILD_DIR)/test-process \
		$(NATIVE_BUILD_DIR)/test-event \
		$(NATIVE_BUILD_DIR)/test-sigpipe
	$(NATIVE_BUILD_DIR)/test-control
	$(NATIVE_BUILD_DIR)/test-process $(NATIVE_BUILD_DIR)/test-hosted-child
	$(NATIVE_BUILD_DIR)/test-event
	$(NATIVE_BUILD_DIR)/test-sigpipe $(NATIVE_CLI)
	$(NATIVE_CLI) --help >$(NATIVE_BUILD_DIR)/help.out
	grep -F -- '--config FILE' $(NATIVE_BUILD_DIR)/help.out
	grep -F -- '--forward LISTEN=BACKEND' $(NATIVE_BUILD_DIR)/help.out
	grep -F -- '--check' $(NATIVE_BUILD_DIR)/help.out
	! grep -E -- '--listen|--backend' $(NATIVE_BUILD_DIR)/help.out
	! $(NATIVE_CLI) --check \
		--forward 203.0.113.10:443=192.0.2.1:8443 --cc bbr \
		2>$(NATIVE_BUILD_DIR)/check-parser.err
	grep -F 'forward backend must use 127.0.0.1:port' \
		$(NATIVE_BUILD_DIR)/check-parser.err
	! $(NATIVE_CLI) --forward 203.0.113.10:443=127.0.0.1:8443 \
		--forward 203.0.113.11:443=127.0.0.1:9443 --cc bbr \
		2>$(NATIVE_BUILD_DIR)/duplicate-port.err
	grep -F 'public listener ports must be unique within one tcpcc process' \
		$(NATIVE_BUILD_DIR)/duplicate-port.err
	! $(NATIVE_CLI) --forward 203.0.113.10:443=127.0.0.1:8443 \
		--forward '[2001:db8::10]:444=127.0.0.1:9443' --cc bbr \
		2>$(NATIVE_BUILD_DIR)/mixed-family.err
	grep -F 'all public listeners in one tcpcc process must use the same address family' \
		$(NATIVE_BUILD_DIR)/mixed-family.err
	! $(NATIVE_CLI) --forward 203.0.113.10:443 \
		--cc bbr 2>$(NATIVE_BUILD_DIR)/malformed-forward.err
	grep -F -- '--forward must use LISTEN=BACKEND syntax' \
		$(NATIVE_BUILD_DIR)/malformed-forward.err
	! $(NATIVE_CLI) --listen 203.0.113.10:443 --cc bbr \
		2>$(NATIVE_BUILD_DIR)/removed-listen.err
	grep -F -- '--forward LISTEN=BACKEND' $(NATIVE_BUILD_DIR)/removed-listen.err
	! $(NATIVE_CLI) --backend 127.0.0.1:8443 --cc bbr \
		2>$(NATIVE_BUILD_DIR)/removed-backend.err
	grep -F -- '--forward LISTEN=BACKEND' $(NATIVE_BUILD_DIR)/removed-backend.err

release-package: $(NATIVE_CLI)
	VMLINUX="$(VMLINUX)" scripts/package-release.sh

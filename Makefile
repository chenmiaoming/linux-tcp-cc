# SPDX-License-Identifier: GPL-2.0-only

PREFIX ?= /usr/local
DESTDIR ?=
VMLINUX ?= .build/tcpcc-bootstrap-out/vmlinux

PYTHON_MODULES := \
	tools/tcpcc_cli.py \
	tools/tcpcc_control.py \
	tools/tcpcc_host.py

.PHONY: install
install:
	test -x "$(VMLINUX)"
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -d "$(DESTDIR)$(PREFIX)/lib/tcpcc"
	install -d "$(DESTDIR)$(PREFIX)/libexec/tcpcc"
	install -m 0755 tcpcc "$(DESTDIR)$(PREFIX)/bin/tcpcc"
	install -m 0644 $(PYTHON_MODULES) "$(DESTDIR)$(PREFIX)/lib/tcpcc/"
	install -m 0755 "$(VMLINUX)" "$(DESTDIR)$(PREFIX)/libexec/tcpcc/vmlinux"

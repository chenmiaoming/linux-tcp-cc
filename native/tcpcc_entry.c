// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>

int tcpcc_cli_main(int argc, char **argv);

static int tcpcc_entry_error(const char *message)
{
	fprintf(stderr, "tcpcc: error: %s\n", message);
	return 1;
}

static int tcpcc_entry_ignore_sigpipe(void)
{
	struct sigaction action = { .sa_handler = SIG_IGN };

	if (sigemptyset(&action.sa_mask) != 0 ||
	    sigaction(SIGPIPE, &action, NULL) != 0)
		return -1;
	return 0;
}

int main(int argc, char **argv)
{
	/*
	 * Runtime status is commonly piped through tee/logger. If that consumer
	 * exits together with the initiating terminal, teardown must still reach
	 * the owned firewall and TUN rollback rather than dying on the first
	 * shutdown log write with SIGPIPE. stdio will instead observe EPIPE while
	 * the supervisor continues through its cleanup path.
	 */
	if (tcpcc_entry_ignore_sigpipe())
		return tcpcc_entry_error("ignoring SIGPIPE failed");
	return tcpcc_cli_main(argc, argv);
}

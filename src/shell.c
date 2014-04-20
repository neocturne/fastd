/*
  Copyright (c) 2012-2014, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include "shell.h"
#include "peer.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/wait.h>


static void shell_command_setenv(fastd_context_t *ctx, pid_t pid, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *peer_addr) {
	/* both INET6_ADDRSTRLEN and IFNAMESIZE already include space for the zero termination, so there is no need to add space for the '%' here. */
	char buf[INET6_ADDRSTRLEN+IF_NAMESIZE];

	snprintf(buf, sizeof(buf), "%u", (unsigned)pid);
	setenv("FASTD_PID", buf, 1);

	if (ctx->ifname) {
		setenv("INTERFACE", ctx->ifname, 1);
	}
	else if (conf.ifname) {
		char ifname[IF_NAMESIZE];

		strncpy(ifname, conf.ifname, sizeof(ifname)-1);
		ifname[sizeof(ifname)-1] = 0;

		setenv("INTERFACE", ifname, 1);
	}
	else {
		unsetenv("INTERFACE");
	}

	snprintf(buf, sizeof(buf), "%u", conf.mtu);
	setenv("INTERFACE_MTU", buf, 1);

	if (peer && peer->config && peer->config->name)
		setenv("PEER_NAME", peer->config->name, 1);
	else
		unsetenv("PEER_NAME");

	switch(local_addr ? local_addr->sa.sa_family : AF_UNSPEC) {
	case AF_INET:
		inet_ntop(AF_INET, &local_addr->in.sin_addr, buf, sizeof(buf));
		setenv("LOCAL_ADDRESS", buf, 1);

		snprintf(buf, sizeof(buf), "%u", ntohs(local_addr->in.sin_port));
		setenv("LOCAL_PORT", buf, 1);

		break;

	case AF_INET6:
		inet_ntop(AF_INET6, &local_addr->in6.sin6_addr, buf, sizeof(buf));

		if (IN6_IS_ADDR_LINKLOCAL(&local_addr->in6.sin6_addr)) {
			if (if_indextoname(local_addr->in6.sin6_scope_id, buf+strlen(buf)+1))
				buf[strlen(buf)] = '%';
		}

		setenv("LOCAL_ADDRESS", buf, 1);

		snprintf(buf, sizeof(buf), "%u", ntohs(local_addr->in6.sin6_port));
		setenv("LOCAL_PORT", buf, 1);

		break;

	default:
		unsetenv("LOCAL_ADDRESS");
		unsetenv("LOCAL_PORT");
	}

	switch(peer_addr ? peer_addr->sa.sa_family : AF_UNSPEC) {
	case AF_INET:
		inet_ntop(AF_INET, &peer_addr->in.sin_addr, buf, sizeof(buf));
		setenv("PEER_ADDRESS", buf, 1);

		snprintf(buf, sizeof(buf), "%u", ntohs(peer_addr->in.sin_port));
		setenv("PEER_PORT", buf, 1);

		break;

	case AF_INET6:
		inet_ntop(AF_INET6, &peer_addr->in6.sin6_addr, buf, sizeof(buf));

		if (IN6_IS_ADDR_LINKLOCAL(&peer_addr->in6.sin6_addr)) {
			if (if_indextoname(peer_addr->in6.sin6_scope_id, buf+strlen(buf)+1))
				buf[strlen(buf)] = '%';
		}

		setenv("PEER_ADDRESS", buf, 1);

		snprintf(buf, sizeof(buf), "%u", ntohs(peer_addr->in6.sin6_port));
		setenv("PEER_PORT", buf, 1);

		break;

	default:
		unsetenv("PEER_ADDRESS");
		unsetenv("PEER_PORT");
	}

	conf.protocol->set_shell_env(peer);
}

static bool shell_command_do_exec(fastd_context_t *ctx, const fastd_shell_command_t *command, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *peer_addr, pid_t *pid_ret) {
	pid_t parent = getpid();

	pid_t pid = fork();
	if (pid < 0) {
		pr_error_errno(ctx, "shell_command_do_exec: fork");
		return false;
	}
	else if (pid > 0) {
		if (pid_ret)
			*pid_ret = pid;

		return true;
	}

	/* child process */

	if (chdir(command->dir))
		_exit(126);

	shell_command_setenv(ctx, parent, peer, local_addr, peer_addr);

	/* unblock SIGCHLD */
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	pthread_sigmask(SIG_UNBLOCK, &set, NULL);

	execl("/bin/sh", "sh", "-c", command->command, (char*)NULL);
	_exit(127);
}

bool fastd_shell_command_exec_sync(fastd_context_t *ctx, const fastd_shell_command_t *command, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *peer_addr, int *ret) {
	if (!fastd_shell_command_isset(command))
		return true;

	/* block SIGCHLD */
	sigset_t set, oldset;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &set, &oldset);

	pid_t pid;
	if (!shell_command_do_exec(ctx, command, peer, local_addr, peer_addr, &pid))
		return false;

	int status;
	pid_t err = waitpid(pid, &status, 0);

	pthread_sigmask(SIG_SETMASK, &oldset, NULL);

	if (err <= 0) {
		pr_error_errno(ctx, "fastd_shell_command_exec_sync: waitpid");
		return false;
	}

	if (ret) {
		*ret = status;
	}
	else {
		if (WIFSIGNALED(status))
			pr_warn(ctx, "command exited with signal %i", WTERMSIG(status));
		else if (WEXITSTATUS(status))
			pr_warn(ctx, "command exited with status %i", WEXITSTATUS(status));
	}

	return true;
}


void fastd_shell_command_exec(fastd_context_t *ctx, const fastd_shell_command_t *command, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *peer_addr) {
	if (!fastd_shell_command_isset(command))
		return;

	if (command->sync)
		fastd_shell_command_exec_sync(ctx, command, peer, local_addr, peer_addr, NULL);
	else
		shell_command_do_exec(ctx, command, peer, local_addr, peer_addr, NULL);
}

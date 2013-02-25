/*
  Copyright (c) 2012-2013, Matthias Schiffer <mschiffer@universe-factory.net>
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


#define _GNU_SOURCE

#include "peer.h"

#include <arpa/inet.h>


bool fastd_shell_exec(fastd_context_t *ctx, const fastd_peer_t *peer, const char *command, const char *dir, int *ret) {
	int result = -1;
	bool ok = false;
	char *cwd = get_current_dir_name();

	if(!chdir(dir)) {
		char buf[INET6_ADDRSTRLEN];

		snprintf(buf, sizeof(buf), "%u", (unsigned)getpid());
		setenv("FASTD_PID", buf, 1);

		setenv("INTERFACE", ctx->ifname, 1);

		snprintf(buf, sizeof(buf), "%u", ctx->conf->mtu);
		setenv("INTERFACE_MTU", buf, 1);

		if (peer && peer->config && peer->config->name)
			setenv("PEER_NAME", peer->config->name, 1);
		else
			unsetenv("PEER_NAME");

		switch((peer && peer->sock) ? peer->sock->addr->addr.sa.sa_family : AF_UNSPEC) {
		case AF_INET:
			inet_ntop(AF_INET, &peer->sock->addr->addr.in.sin_addr, buf, sizeof(buf));
			setenv("LOCAL_ADDRESS", buf, 1);

			snprintf(buf, sizeof(buf), "%u", ntohs(peer->sock->addr->addr.in.sin_port));
			setenv("LOCAL_PORT", buf, 1);

			break;

		case AF_INET6:
			inet_ntop(AF_INET6, &peer->sock->addr->addr.in6.sin6_addr, buf, sizeof(buf));
			setenv("LOCAL_ADDRESS", buf, 1);

			snprintf(buf, sizeof(buf), "%u", ntohs(peer->sock->addr->addr.in6.sin6_port));
			setenv("LOCAL_PORT", buf, 1);

			break;

		default:
			unsetenv("LOCAL_ADDRESS");
			unsetenv("LOCAL_PORT");
		}

		switch(peer ? peer->address.sa.sa_family : AF_UNSPEC) {
		case AF_INET:
			inet_ntop(AF_INET, &peer->address.in.sin_addr, buf, sizeof(buf));
			setenv("PEER_ADDRESS", buf, 1);

			snprintf(buf, sizeof(buf), "%u", ntohs(peer->address.in.sin_port));
			setenv("PEER_PORT", buf, 1);

			break;

		case AF_INET6:
			inet_ntop(AF_INET6, &peer->address.in6.sin6_addr, buf, sizeof(buf));
			setenv("PEER_ADDRESS", buf, 1);

			snprintf(buf, sizeof(buf), "%u", ntohs(peer->address.in6.sin6_port));
			setenv("PEER_PORT", buf, 1);

			break;

		default:
			unsetenv("PEER_ADDRESS");
			unsetenv("PEER_PORT");
		}

		ctx->conf->protocol->set_shell_env(ctx, peer);

		result = system(command);

		if (ret) {
			*ret = result;
			ok = true;
		}
		else {
			if (WIFSIGNALED(result))
				pr_error(ctx, "command exited with signal %i", WTERMSIG(result));
			else if (WEXITSTATUS(result))
				pr_warn(ctx, "command exited with status %i", WEXITSTATUS(ret));
			else
				ok = true;
		}

		if(chdir(cwd))
			pr_error(ctx, "can't chdir to `%s': %s", cwd, strerror(errno));
	}
	else {
		pr_error(ctx, "can't chdir to `%s': %s", dir, strerror(errno));
	}

	free(cwd);

	return ok;
}

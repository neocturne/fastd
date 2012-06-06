/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
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

#include "fastd.h"
#include "peer.h"

#include <netdb.h>
#include <pthread.h>
#include <unistd.h>


typedef struct _resolv_arg {
	fastd_context *ctx;
	pthread_t master_thread;
	char *hostname;
	fastd_peer_address constraints;
} resolv_arg;


static void* resolve_peer(void *varg) {
	resolv_arg *arg = varg;

	struct addrinfo hints;
	struct addrinfo *res = NULL;
	int gai_ret;
	bool error = false;

	char portstr[6];
	snprintf(portstr, 6, "%u", ntohs(arg->constraints.in.sin_port));

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = arg->constraints.sa.sa_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;

	gai_ret = getaddrinfo(arg->hostname, portstr, &hints, &res);

	if (gai_ret || !res) {
		pr_verbose(arg->ctx, "resolving host `%s' failed: %s", arg->hostname, gai_strerror(gai_ret));
		error = true;
	}
	else if (res->ai_addrlen > sizeof(fastd_peer_address) || (res->ai_addr->sa_family != AF_INET && res->ai_addr->sa_family != AF_INET6)) {
		pr_warn(arg->ctx, "resolving host `%s': unsupported address returned", arg->hostname);
		error = true;
	}

	fastd_resolve_return ret;
	memset(&ret, 0, sizeof(ret));

	ret.hostname = arg->hostname;
	ret.constraints = arg->constraints;

	if (!error) {
		pr_verbose(arg->ctx, "resolved host `%s' successfully", arg->hostname);
		memcpy(&ret.addr, res->ai_addr, res->ai_addrlen);
	}
	else {
		ret.addr.sa.sa_family = AF_UNSPEC;
	}

	if (write(arg->ctx->resolvewfd, &ret, sizeof(ret)) < 0)
		pr_error_errno(arg->ctx, "can't write resolve return");

	freeaddrinfo(res);
	free(arg);

	return NULL;
}

void fastd_resolve_peer(fastd_context *ctx, fastd_peer *peer) {
	if (timespec_after(&peer->last_resolve, &peer->last_resolve_return)) {
		pr_debug(ctx, "not resolving %P as there is already a resolve running", peer);
		return;
	}

	if (timespec_diff(&ctx->now, &peer->last_resolve) < ctx->conf->min_resolve_interval*1000) {
		pr_debug(ctx, "not resolving %P as it has been resolved a short time ago", peer);

		fastd_resolve_return ret;
		memset(&ret, 0, sizeof(ret));

		ret.hostname = strdup(peer->config->hostname);
		ret.constraints = peer->config->address;
		ret.addr = peer->address;

		if (write(ctx->resolvewfd, &ret, sizeof(ret)) < 0)
			pr_error_errno(ctx, "can't write resolve return");

		return;
	}

	pr_verbose(ctx, "resolving host `%s' for peer %P...", peer->config->hostname, peer);
	peer->last_resolve = ctx->now;

	resolv_arg *arg = malloc(sizeof(resolv_arg));

	arg->ctx = ctx;
	arg->master_thread = pthread_self();
	arg->hostname = strdup(peer->config->hostname);
	arg->constraints = peer->config->address;

	pthread_t thread;
	if (pthread_create(&thread, NULL, resolve_peer, arg) != 0) {
		pr_error_errno(ctx, "unable to create resolver thread");
		free(arg->hostname);
		free(arg);
	}

	pthread_detach(thread);
}

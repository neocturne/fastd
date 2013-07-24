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

#include "fastd.h"
#include "peer.h"

#include <netdb.h>
#include <pthread.h>


typedef struct resolv_arg {
	fastd_context_t *ctx;
	char *hostname;
	fastd_peer_address_t constraints;
} resolv_arg_t;


static void* resolve_peer(void *varg) {
	resolv_arg_t *arg = varg;

	struct addrinfo *res = NULL;
	int gai_ret;
	bool error = false;

	char portstr[6];
	snprintf(portstr, 6, "%u", ntohs(arg->constraints.in.sin_port));

	struct addrinfo hints = {
		.ai_family = arg->constraints.sa.sa_family,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG,
	};

	gai_ret = getaddrinfo(arg->hostname, portstr, &hints, &res);

	if (gai_ret || !res) {
		pr_verbose(arg->ctx, "resolving host `%s' failed: %s", arg->hostname, gai_strerror(gai_ret));
		error = true;
	}
	else if (res->ai_addrlen > sizeof(fastd_peer_address_t) || (res->ai_addr->sa_family != AF_INET && res->ai_addr->sa_family != AF_INET6)) {
		pr_warn(arg->ctx, "resolving host `%s': unsupported address returned", arg->hostname);
		error = true;
	}

	size_t hostname_len = strlen(arg->hostname);
	char buf[sizeof(fastd_resolve_return_t) + hostname_len];

	fastd_resolve_return_t *ret = (void*)buf;
	char *hostname = buf + sizeof(fastd_resolve_return_t);

	memset(ret, 0, sizeof(fastd_resolve_return_t));

	ret->constraints = arg->constraints;
	ret->hostname_len = hostname_len;
	memcpy(hostname, arg->hostname, hostname_len);

	if (!error) {
		pr_verbose(arg->ctx, "resolved host `%s' successfully", arg->hostname);
		memcpy(&ret->addr, res->ai_addr, res->ai_addrlen);
		fastd_peer_address_simplify(&ret->addr);
	}
	else {
		ret->addr.sa.sa_family = AF_UNSPEC;
	}

	if (write(arg->ctx->resolvewfd, buf, sizeof(buf)) < 0)
		pr_error_errno(arg->ctx, "can't write resolve return");

	freeaddrinfo(res);
	free(arg->hostname);
	free(arg);

	return NULL;
}

void fastd_resolve_peer(fastd_context_t *ctx, fastd_peer_t *peer, fastd_remote_t *remote) {
	if (!peer->config)
		exit_bug(ctx, "trying to resolve temporary peer");

	if (timespec_after(&remote->last_resolve, &remote->last_resolve_return)) {
		pr_debug(ctx, "not resolving %P as there is already a resolve running", peer);
		return;
	}

	if (timespec_diff(&ctx->now, &remote->last_resolve) < ctx->conf->min_resolve_interval*1000) {
		/* last resolve was just a few seconds ago */
		return;
	}

	pr_verbose(ctx, "resolving host `%s' for peer %P...", remote->config->hostname, peer);

	resolv_arg_t *arg = malloc(sizeof(resolv_arg_t));

	arg->ctx = ctx;
	arg->hostname = strdup(remote->config->hostname);
	arg->constraints = remote->config->address;

	pthread_t thread;
	if (pthread_create(&thread, NULL, resolve_peer, arg) != 0) {
		pr_error_errno(ctx, "unable to create resolver thread");

		free(arg->hostname);
		free(arg);

		return;
	}

	pthread_detach(thread);
	remote->last_resolve = ctx->now;
}

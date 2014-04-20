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


#include "fastd.h"
#include "peer.h"
#include "async.h"

#include <netdb.h>
#include <pthread.h>


typedef struct resolv_arg {
	fastd_context_t *ctx;
	fastd_remote_t *remote;
	char *hostname;
	fastd_peer_address_t constraints;
} resolv_arg_t;


static void* resolve_peer(void *varg) {
	resolv_arg_t *arg = varg;

	struct addrinfo *res = NULL, *res2;
	size_t n_addr = 0;
	int gai_ret;

	char portstr[6];
	snprintf(portstr, 6, "%u", ntohs(arg->constraints.in.sin_port));

	struct addrinfo hints = {
		.ai_family = arg->constraints.sa.sa_family,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = AI_NUMERICSERV
#ifdef HAVE_AI_ADDRCONFIG
		| AI_ADDRCONFIG
#endif
	};

	gai_ret = getaddrinfo(arg->hostname, portstr, &hints, &res);

	if (gai_ret || !res) {
		pr_verbose(arg->ctx, "resolving host `%s' failed: %s", arg->hostname, gai_strerror(gai_ret));
	}
	else {
		for (res2 = res; res2; res2 = res2->ai_next)
			n_addr++;
	}

	uint8_t retbuf[sizeof(fastd_async_resolve_return_t) + n_addr*sizeof(fastd_peer_address_t)] __attribute__((aligned(8)));
	fastd_async_resolve_return_t *ret = (fastd_async_resolve_return_t*)retbuf;
	ret->remote = arg->remote;

	if (n_addr) {
		n_addr = 0;
		for (res2 = res; res2; res2 = res2->ai_next) {
			if (res2->ai_addrlen > sizeof(fastd_peer_address_t) || (res2->ai_addr->sa_family != AF_INET && res2->ai_addr->sa_family != AF_INET6)) {
				pr_warn(arg->ctx, "resolving host `%s': unsupported address returned", arg->hostname);
				continue;
			}

			memset(&ret->addr[n_addr], 0, sizeof(fastd_peer_address_t));
			memcpy(&ret->addr[n_addr], res2->ai_addr, res2->ai_addrlen);
			fastd_peer_address_simplify(&ret->addr[n_addr]);

			n_addr++;
		}

		if (n_addr)
			pr_verbose(arg->ctx, "resolved host `%s' successfully", arg->hostname);
	}

	ret->n_addr = n_addr;

	fastd_async_enqueue(arg->ctx, ASYNC_TYPE_RESOLVE_RETURN, ret, sizeof(fastd_async_resolve_return_t) + n_addr*sizeof(fastd_peer_address_t));

	freeaddrinfo(res);
	free(arg->hostname);
	free(arg);

	return NULL;
}

void fastd_resolve_peer(fastd_context_t *ctx, fastd_peer_t *peer, fastd_remote_t *remote) {
	if (!peer->config)
		exit_bug(ctx, "trying to resolve temporary peer");

	if (remote->resolving) {
		pr_debug(ctx, "not resolving %P as there is already a resolve running", peer);
		return;
	}

	if (!fastd_timed_out(ctx, &remote->last_resolve_timeout)) {
		/* last resolve was just a few seconds ago */
		return;
	}

	pr_verbose(ctx, "resolving host `%s' for peer %P...", remote->config->hostname, peer);

	fastd_remote_ref(remote);
	remote->last_resolve_timeout = fastd_in_seconds(ctx, conf.min_resolve_interval);
	remote->resolving = true;

	resolv_arg_t *arg = malloc(sizeof(resolv_arg_t));

	arg->ctx = ctx;
	arg->remote = remote;
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
}

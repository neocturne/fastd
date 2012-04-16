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
#include <signal.h>


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
#ifdef AI_IDN
	hints.ai_flags |= AI_IDN;
#endif

	gai_ret = getaddrinfo(arg->hostname, portstr, &hints, &res);

	if (gai_ret) {
		pr_debug(arg->ctx, "Resolving host `%s' failed: %s", arg->hostname, gai_strerror(gai_ret));
		error = true;
	}
	else if (res->ai_addrlen > sizeof(fastd_peer_address)) {
		pr_warn(arg->ctx, "Resolving host `%s': unsupported address returned", arg->hostname);
		error = true;
	}

	fastd_resolve_return *ret = malloc(sizeof(fastd_resolve_return));

	ret->ctx = arg->ctx;

	ret->hostname = arg->hostname;
	ret->constraints = arg->constraints;

	if (!error) {
		pr_debug(arg->ctx, "Resolved host `%s' successfully", arg->hostname);
		memcpy(&ret->addr, res->ai_addr, res->ai_addrlen);
	}
	else {
		ret->addr.sa.sa_family = AF_UNSPEC;
	}

	union sigval sigval;
	sigval.sival_ptr = ret;
	if (pthread_sigqueue(arg->master_thread, SIGUSR1, sigval))
		exit_errno(arg->ctx, "pthread_sigqueue");

	freeaddrinfo(res);
	free(arg);

	return NULL;
}

void fastd_resolve_peer(fastd_context *ctx, const fastd_peer_config *peer) {
	pr_debug(ctx, "Resolving host `%s' for peer `%s'...", peer->hostname, peer->name);

	resolv_arg *arg = malloc(sizeof(resolv_arg));

	arg->ctx = ctx;
	arg->master_thread = pthread_self();
	arg->hostname = strdup(peer->hostname);
	arg->constraints = peer->address;

	pthread_t thread;
	if (pthread_create(&thread, NULL, resolve_peer, arg) != 0) {
		pr_error_errno(ctx, "unable to create resolver thread");
		free(arg->hostname);
		free(arg);
	}

	pthread_detach(thread);
}

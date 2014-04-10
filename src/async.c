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


#include "async.h"
#include "fastd.h"


void fastd_async_init(fastd_context_t *ctx) {
	fastd_open_pipe(ctx, &ctx->async_rfd, &ctx->async_wfd);
}

static void handle_resolve_return(fastd_context_t *ctx) {
	fastd_async_resolve_return_t resolve_return;
	while (read(ctx->async_rfd, &resolve_return, sizeof(resolve_return)) < 0) {
		if (errno != EINTR)
			exit_errno(ctx, "handle_resolve_return: read");
	}

	fastd_peer_address_t addresses[resolve_return.n_addr];
	while (read(ctx->async_rfd, &addresses, sizeof(addresses)) < 0) {
		if (errno != EINTR)
			exit_errno(ctx, "handle_resolve_return: read");
	}

	fastd_peer_t *peer;
	for (peer = ctx->peers; peer; peer = peer->next) {
		if (!peer->config)
			continue;

		fastd_remote_t *remote;
		for (remote = peer->remotes; remote; remote = remote->next) {
			if (remote == resolve_return.remote)
				break;
		}

		if (!remote)
			continue;

		fastd_peer_handle_resolve(ctx, peer, remote, resolve_return.n_addr, addresses);

		break;
	}

	fastd_remote_unref(resolve_return.remote);
}

void fastd_async_handle(fastd_context_t *ctx) {
	fastd_async_type_t type;

	while (read(ctx->async_rfd, &type, sizeof(type)) < 0) {
		if (errno != EINTR)
			exit_errno(ctx, "fastd_async_handle: read");
	}

	switch (type) {
	case ASYNC_TYPE_RESOLVE_RETURN:
		handle_resolve_return(ctx);
		break;

	default:
		exit_bug(ctx, "fastd_async_handle: unknown type");
	}
}

void fastd_async_enqueue(fastd_context_t *ctx, fastd_async_type_t type, const void *data, size_t len) {
	struct iovec vec[2] = {
		{ .iov_base = &type, .iov_len = sizeof(type) },
		{ .iov_base = (void *)data, .iov_len = len },
	};

	if (writev(ctx->async_wfd, vec, 2) < 0)
		pr_error_errno(ctx, "fastd_async_enqueue");
}

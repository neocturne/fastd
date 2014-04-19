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


#include "poll.h"
#include "async.h"
#include "peer.h"


void fastd_poll_init(fastd_context_t *ctx) {
	VECTOR_ALLOC(ctx->pollfds, 2 + ctx->n_socks);

	VECTOR_INDEX(ctx->pollfds, 0) = (struct pollfd) {
		.fd = -1,
		.events = POLLIN,
		.revents = 0,
	};

	VECTOR_INDEX(ctx->pollfds, 1) = (struct pollfd) {
		.fd = ctx->async_rfd,
		.events = POLLIN,
		.revents = 0,
	};

	size_t i;
	for (i = 0; i < ctx->n_socks; i++) {
		VECTOR_INDEX(ctx->pollfds, 2+i) = (struct pollfd) {
			.fd = -1,
			.events = POLLIN,
			.revents = 0,
		};
	}
}

void fastd_poll_free(fastd_context_t *ctx) {
	VECTOR_FREE(ctx->pollfds);
}


void fastd_poll_set_fd_tuntap(fastd_context_t *ctx, int fd) {
	VECTOR_INDEX(ctx->pollfds, 0).fd = fd;
}

void fastd_poll_set_fd_sock(fastd_context_t *ctx, int fd, size_t i) {
	VECTOR_INDEX(ctx->pollfds, 2+i).fd = fd;
}

void fastd_poll_set_fd_peer(fastd_context_t *ctx, int fd, size_t i) {
	VECTOR_INDEX(ctx->pollfds, 2+ctx->n_socks+i).fd = fd;
}

void fastd_poll_add_peer(fastd_context_t *ctx) {
	struct pollfd pollfd = {
		.fd = -1,
		.events = POLLIN,
		.revents = 0,
	};

	VECTOR_ADD(ctx->pollfds, pollfd);
}

void fastd_poll_delete_peer(fastd_context_t *ctx, size_t i) {
	VECTOR_DELETE(ctx->pollfds, 2+ctx->n_socks+i);
}


static inline bool handle_tun_tap(fastd_context_t *ctx, fastd_buffer_t buffer) {
	if (ctx->conf->mode != MODE_TAP)
		return false;

	if (buffer.len < ETH_HLEN) {
		pr_debug(ctx, "truncated packet on tap interface");
		fastd_buffer_free(buffer);
		return true;
	}

	fastd_eth_addr_t dest_addr = fastd_get_dest_address(ctx, buffer);
	if (!fastd_eth_addr_is_unicast(dest_addr))
		return false;

	fastd_peer_t *peer = fastd_peer_find_by_eth_addr(ctx, dest_addr);

	if (!peer)
		return false;

	ctx->conf->protocol->send(ctx, peer, buffer);
	return true;
}

static void handle_tun(fastd_context_t *ctx) {
	fastd_buffer_t buffer = fastd_tuntap_read(ctx);
	if (!buffer.len)
		return;

	if (handle_tun_tap(ctx, buffer))
		return;

	/* TUN mode or multicast packet */
	fastd_send_all(ctx, NULL, buffer);
}

static inline int handshake_timeout(fastd_context_t *ctx) {
	if (!ctx->handshake_queue.next)
		return -1;

	fastd_peer_t *peer = container_of(ctx->handshake_queue.next, fastd_peer_t, handshake_entry);

	int diff_msec = timespec_diff(&peer->next_handshake, &ctx->now);
	if (diff_msec < 0)
		return 0;
	else
		return diff_msec;
}

void fastd_poll_handle(fastd_context_t *ctx) {
	int maintenance_timeout = timespec_diff(&ctx->next_maintenance, &ctx->now);

	if (maintenance_timeout < 0)
		maintenance_timeout = 0;

	int timeout = handshake_timeout(ctx);
	if (timeout < 0 || timeout > maintenance_timeout)
		timeout = maintenance_timeout;

	int ret = poll(VECTOR_DATA(ctx->pollfds), VECTOR_LEN(ctx->pollfds), timeout);
	if (ret < 0) {
		if (errno == EINTR)
			return;

		exit_errno(ctx, "poll");
	}

	fastd_update_time(ctx);

	if (VECTOR_INDEX(ctx->pollfds, 0).revents & POLLIN)
		handle_tun(ctx);
	if (VECTOR_INDEX(ctx->pollfds, 1).revents & POLLIN)
		fastd_async_handle(ctx);

	size_t i;
	for (i = 0; i < ctx->n_socks; i++) {
		if (VECTOR_INDEX(ctx->pollfds, 2+i).revents & (POLLERR|POLLHUP|POLLNVAL)) {
			fastd_socket_error(ctx, &ctx->socks[i]);
			VECTOR_INDEX(ctx->pollfds, 2+i).fd = -1;
		}
		else if (VECTOR_INDEX(ctx->pollfds, 2+i).revents & POLLIN) {
			fastd_receive(ctx, &ctx->socks[i]);
		}
	}

	for (i = 0; i < VECTOR_LEN(ctx->peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx->peers, i);

		if (VECTOR_INDEX(ctx->pollfds, 2+ctx->n_socks+i).revents & (POLLERR|POLLHUP|POLLNVAL)) {
			fastd_peer_reset_socket(ctx, peer);
		}
		else if (VECTOR_INDEX(ctx->pollfds, 2+ctx->n_socks+i).revents & POLLIN) {
			fastd_receive(ctx, peer->sock);
		}
	}
}
